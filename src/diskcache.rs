//! Disk-backed cache storage — a production-usable `pingora_cache::Storage`.
//!
//! Cloudflare only ships an in-memory `MemCache` ("testing only, not for
//! production"); this stores each entry as ONE file under a 2-level sharded
//! directory (`<ab>/<cd>/<hash>.ent`):
//!
//! ```text
//! [u64 body-size][u32 internal-len][u32 header-len][internal][header][body]
//! ```
//!
//! Every filesystem operation is done relative to a pinned root directory FD
//! (`crate::dirs::SecureDir`) via `openat`/`renameat`/`unlinkat`, one component
//! at a time with `O_NOFOLLOW`. A local user who can write the cache dir can
//! therefore neither reroute a write by swapping a shard for a symlink (the open
//! fails) nor make the reaper delete a file outside the tree. The entry is
//! written to an unpredictably-named `O_EXCL` temp, fsync'd, and published with
//! a SINGLE `renameat`, so a crash leaves either the previous complete entry or
//! none — meta and body share one file and can't disagree.
//!
//! Streaming partial writes are not supported, so a reader never sees an entry
//! until the writer finishes. A background reaper bounds total size / file count
//! / free space and clears temp files + legacy (`.meta`/`.body`) entries; it
//! only ever touches files matching the cache's exact naming.

use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use bytes::Bytes;
use pingora_cache::key::{CacheHashKey, CompactCacheKey};
use pingora_cache::storage::{
    HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeType, Storage,
};
use pingora_cache::trace::SpanHandle;
use pingora_cache::{CacheKey, CacheMeta};
use pingora_error::{Error, ErrorType, Result};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::dirs::SecureDir;

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Sanity cap on the serialized meta (internal + header) length read back from
/// disk — a corrupt length field must not trigger a huge allocation.
const MAX_META_LEN: usize = 1024 * 1024;

const PREFIX_LEN: usize = 16;

fn err(ctx: &'static str) -> impl FnOnce(std::io::Error) -> Box<Error> {
    move |e| Error::because(ErrorType::InternalError, ctx, e)
}

/// An unpredictable temp name: `.tmp.<pid>.<seq>.<nanos>`. Combined with the
/// `O_EXCL` create in `SecureDir`, a local attacker can't pre-create the name to
/// win the race — a losing race is an error, never a followed symlink.
fn tmp_name() -> String {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!(".tmp.{}.{seq}.{nanos}", std::process::id())
}

fn encode_prefix(body_size: u64, il: usize, hl: usize) -> [u8; PREFIX_LEN] {
    let mut p = [0u8; PREFIX_LEN];
    p[0..8].copy_from_slice(&body_size.to_le_bytes());
    p[8..12].copy_from_slice(&(il as u32).to_le_bytes());
    p[12..16].copy_from_slice(&(hl as u32).to_le_bytes());
    p
}

fn decode_prefix(p: &[u8; PREFIX_LEN]) -> (u64, usize, usize) {
    let body_size = u64::from_le_bytes(p[0..8].try_into().unwrap());
    let il = u32::from_le_bytes(p[8..12].try_into().unwrap()) as usize;
    let hl = u32::from_le_bytes(p[12..16].try_into().unwrap()) as usize;
    (body_size, il, hl)
}

pub struct DiskCache {
    root: Arc<SecureDir>,
}

impl DiskCache {
    pub fn new(root: Arc<SecureDir>) -> Self {
        DiskCache { root }
    }

    /// Open the 2-level shard dir for a key hash, CREATING it — write path only
    /// (a miss). `combined()` is 32 hex chars so [0..4] is always hex.
    fn shard_create(&self, hash: &str) -> std::io::Result<SecureDir> {
        self.root.sub(&hash[0..2])?.sub(&hash[2..4])
    }

    /// Open the shard dir WITHOUT creating it — read/lookup/purge paths. A
    /// missing shard is a miss, so a lookup for an absent key never mints empty
    /// directories (which the reaper would then have to scan forever).
    fn shard_open(&self, hash: &str) -> std::io::Result<SecureDir> {
        self.root.sub_open(&hash[0..2])?.sub_open(&hash[2..4])
    }
}

fn entry_file(hash: &str) -> String {
    format!("{hash}.ent")
}

// ---- hit handler: stream the body out of the entry file ----
// The file cursor is already positioned at the body offset by `lookup`.

struct DiskHit {
    file: tokio::fs::File,
    buf: Vec<u8>,
    weight: usize,
}

#[async_trait]
impl HandleHit for DiskHit {
    async fn read_body(&mut self) -> Result<Option<Bytes>> {
        let n = self
            .file
            .read(&mut self.buf)
            .await
            .map_err(err("disk cache read"))?;
        if n == 0 {
            Ok(None)
        } else {
            Ok(Some(Bytes::copy_from_slice(&self.buf[..n])))
        }
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &SpanHandle,
    ) -> Result<()> {
        Ok(())
    }

    fn get_eviction_weight(&self) -> usize {
        self.weight
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}

// ---- miss handler: build the whole entry in a temp, one renameat on finish ----

struct DiskMiss {
    file: Option<tokio::fs::File>,
    shard: SecureDir,
    tmp: String,
    entry: String,
    written: usize,
    done: bool,
}

#[async_trait]
impl HandleMiss for DiskMiss {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> Result<()> {
        if let Some(f) = self.file.as_mut() {
            f.write_all(&data)
                .await
                .map_err(err("disk cache write body"))?;
            self.written += data.len();
        }
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> Result<MissFinishType> {
        let mut f = self
            .file
            .take()
            .ok_or_else(|| Error::new_str("disk cache: miss handler already finished"))?;
        f.flush().await.map_err(err("disk cache flush"))?;
        // Patch the real body size into the prefix (written as 0 at create time).
        f.seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(err("disk cache seek"))?;
        f.write_all(&(self.written as u64).to_le_bytes())
            .await
            .map_err(err("disk cache stamp size"))?;
        f.sync_all().await.map_err(err("disk cache fsync"))?;
        drop(f);
        // ONE atomic publish via renameat within the pinned shard dir.
        self.shard
            .rename(&self.tmp, &self.entry)
            .map_err(err("disk cache publish"))?;
        let _ = self.shard.sync();
        self.done = true;
        Ok(MissFinishType::Created(self.written))
    }
}

impl Drop for DiskMiss {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.shard.remove(&self.tmp);
        }
    }
}

/// Read + validate an entry file (relative to `shard`): parsed meta + the file
/// with its cursor at the body offset. Any IO/decode/length problem → None.
async fn open_entry(shard: &SecureDir, name: &str) -> Option<(CacheMeta, tokio::fs::File, u64)> {
    let mut file = tokio::fs::File::from_std(shard.open_read(name).ok()?);
    let mut prefix = [0u8; PREFIX_LEN];
    file.read_exact(&mut prefix).await.ok()?;
    let (body_size, il, hl) = decode_prefix(&prefix);
    if il.checked_add(hl)? > MAX_META_LEN {
        return None;
    }
    let mut meta_buf = vec![0u8; il + hl];
    file.read_exact(&mut meta_buf).await.ok()?;
    let meta = CacheMeta::deserialize(&meta_buf[..il], &meta_buf[il..]).ok()?;
    let actual = file.metadata().await.ok()?.len();
    if actual != (PREFIX_LEN + il + hl) as u64 + body_size {
        return None;
    }
    Some((meta, file, body_size))
}

#[async_trait]
impl Storage for DiskCache {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        let hash = key.combined();
        let Ok(shard) = self.shard_open(&hash) else {
            return Ok(None);
        };
        // Any IO/parse problem is a miss (robust, never fails a request).
        let Some((meta, file, body_size)) = open_entry(&shard, &entry_file(&hash)).await else {
            return Ok(None);
        };
        let hit = DiskHit {
            file,
            buf: vec![0u8; 64 * 1024],
            weight: body_size as usize,
        };
        Ok(Some((meta, Box::new(hit))))
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<MissHandler> {
        let hash = key.combined();
        let shard = self.shard_create(&hash).map_err(err("disk cache mkdir"))?;
        let (internal, header) = meta.serialize()?;
        let tmp = tmp_name();
        let mut file =
            tokio::fs::File::from_std(shard.create_new(&tmp).map_err(err("disk cache create"))?);
        // Body size stamped at finish; 0 for now.
        file.write_all(&encode_prefix(0, internal.len(), header.len()))
            .await
            .map_err(err("disk cache write prefix"))?;
        file.write_all(&internal)
            .await
            .map_err(err("disk cache write meta"))?;
        file.write_all(&header)
            .await
            .map_err(err("disk cache write meta"))?;
        Ok(Box::new(DiskMiss {
            file: Some(file),
            shard,
            tmp,
            entry: entry_file(&hash),
            written: 0,
            done: false,
        }))
    }

    async fn purge(
        &'static self,
        key: &CompactCacheKey,
        _purge_type: PurgeType,
        _trace: &SpanHandle,
    ) -> Result<bool> {
        let hash = key.combined();
        let Ok(shard) = self.shard_open(&hash) else {
            return Ok(false);
        };
        Ok(shard.remove(&entry_file(&hash)).is_ok())
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<bool> {
        // Rebuild the entry with new meta + existing body, published by the same
        // single-renameat swap as a fresh write.
        let hash = key.combined();
        let name = entry_file(&hash);
        let Ok(shard) = self.shard_open(&hash) else {
            return Ok(false);
        };
        let Some((_, mut old, _)) = open_entry(&shard, &name).await else {
            return Ok(false);
        };
        let (internal, header) = meta.serialize()?;
        let tmp = tmp_name();
        let res: std::result::Result<(), std::io::Error> = async {
            let mut f = tokio::fs::File::from_std(shard.create_new(&tmp)?);
            f.write_all(&encode_prefix(0, internal.len(), header.len()))
                .await?;
            f.write_all(&internal).await?;
            f.write_all(&header).await?;
            let copied = tokio::io::copy(&mut old, &mut f).await?;
            f.seek(std::io::SeekFrom::Start(0)).await?;
            f.write_all(&copied.to_le_bytes()).await?;
            f.sync_all().await
        }
        .await;
        match res {
            Ok(()) => {
                shard
                    .rename(&tmp, &name)
                    .map_err(err("disk cache update"))?;
                let _ = shard.sync();
                Ok(true)
            }
            Err(e) => {
                let _ = shard.remove(&tmp);
                Err(err("disk cache update meta")(e))
            }
        }
    }

    fn support_streaming_partial_write(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

// ---- background reaper: bound total on-disk size ----

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Entry,  // <hash>.ent — an evictable cache entry
    Tmp,    // .tmp.<pid>.<seq>.<nanos> — our own in-progress write
    Legacy, // <hash>.meta / <hash>.body — retired layout, reaped on sight
}

// (l1 shard, l2 shard, filename, size, mtime, kind)
type Entry = (String, String, String, u64, SystemTime, Kind);

/// Is `s` a 32-char lowercase-hex cache hash (`CacheHashKey::combined()`)?
fn is_hash(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Is `s` a 2-char lowercase-hex shard name?
fn is_shard(s: &str) -> bool {
    s.len() == 2
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Classify a filename as one the cache OWNS, or `None` to leave it alone. A
/// temp is STRICTLY `.tmp.<digits>.<digits>.<digits>` — a foreign `.tmp.notes`
/// must NOT be treated as ours and deleted (a review finding).
fn classify(name: &str) -> Option<Kind> {
    if let Some(rest) = name.strip_prefix(".tmp.") {
        let parts: Vec<&str> = rest.split('.').collect();
        let ours = parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        return ours.then_some(Kind::Tmp);
    }
    let (stem, ext) = name.rsplit_once('.')?;
    match ext {
        "ent" if is_hash(stem) => Some(Kind::Entry),
        "meta" | "body" if is_hash(stem) => Some(Kind::Legacy),
        _ => None,
    }
}

/// Every 30s, bound the cache (total size / file count / free space) by evicting
/// oldest entries; reap stale temps and legacy files. Only ever touches
/// cache-owned names, and does every delete via the pinned root fd, so a
/// swapped-in symlink can't redirect a delete outside the tree.
pub fn spawn_reaper(root: Arc<SecureDir>, max_size: u64, max_files: u64, min_free: u64) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(30));
        reap(&root, max_size, max_files, min_free);
    });
}

/// Collect cache-owned files by walking `root` two shard levels deep, all via
/// the pinned fd (`entries`/`sub_open`/`stat` are `*at`-relative + `O_NOFOLLOW`,
/// and NEVER create — the reaper must not mint directories).
fn collect(root: &SecureDir, out: &mut Vec<Entry>, total: &mut u64) {
    let Ok(l1s) = root.entries() else { return };
    for l1 in l1s {
        if !is_shard(&l1) || !root.stat(&l1).map(|s| s.0 && !s.1).unwrap_or(false) {
            continue;
        }
        let Ok(d1) = root.sub_open(&l1) else { continue };
        let Ok(l2s) = d1.entries() else { continue };
        for l2 in l2s {
            if !is_shard(&l2) || !d1.stat(&l2).map(|s| s.0 && !s.1).unwrap_or(false) {
                continue;
            }
            let Ok(d2) = d1.sub_open(&l2) else { continue };
            let Ok(names) = d2.entries() else { continue };
            for name in names {
                let Some(kind) = classify(&name) else {
                    continue;
                };
                // stat NOFOLLOW; skip anything that isn't a plain file.
                let Ok((is_dir, is_link, size, mtime)) = d2.stat(&name) else {
                    continue;
                };
                if is_dir || is_link {
                    continue;
                }
                *total += size;
                out.push((l1.clone(), l2.clone(), name, size, mtime, kind));
            }
        }
    }
}

fn remove_entry(root: &SecureDir, e: &Entry) -> bool {
    let Ok(d1) = root.sub_open(&e.0) else {
        return false;
    };
    let Ok(d2) = d1.sub_open(&e.1) else {
        return false;
    };
    let ok = d2.remove(&e.2).is_ok();
    if ok {
        let _ = d2.sync();
    }
    ok
}

fn reap(root: &SecureDir, max_size: u64, max_files: u64, min_free: u64) {
    let now = SystemTime::now();
    let mut entries: Vec<Entry> = Vec::new();
    let mut total_size: u64 = 0;
    collect(root, &mut entries, &mut total_size);

    // 1) Delete stale temps (a hard kill left them; a fresh temp is an
    //    in-progress write, kept but counted) and legacy files on sight.
    entries.retain(|e| {
        let stale_tmp = e.5 == Kind::Tmp
            && now
                .duration_since(e.4)
                .map(|d| d > Duration::from_secs(300))
                .unwrap_or(false);
        if stale_tmp || e.5 == Kind::Legacy {
            if remove_entry(root, e) {
                total_size = total_size.saturating_sub(e.3);
            }
            false
        } else {
            true
        }
    });

    // 2) Evict oldest until under every bound. Only sort (O(n log n)) when we
    //    actually need to evict — a cache under all bounds costs just the scan.
    let mut count = entries.len() as u64;
    let avail = avail_bytes(root).unwrap_or(u64::MAX);
    if total_size <= max_size && count <= max_files && avail >= min_free {
        return;
    }
    entries.sort_by_key(|e| e.4); // oldest first
                                  // Evict to ~90% of the cap but never below 1 (a tiny `max-files` would
                                  // otherwise round its target to 0 and wipe the whole cache).
    let size_target = (max_size / 10 * 9).max(1);
    let count_target = (max_files - max_files / 10).max(1);
    let mut to_free_for_space = min_free.saturating_sub(avail);
    if to_free_for_space > total_size {
        to_free_for_space = 0; // floor unachievable — don't wipe the cache
    }
    // Empty shard dirs left by eviction are NOT reclaimed here: doing so races a
    // concurrent writer that has opened a fresh (still-empty) shard but not yet
    // written its temp file (rmdir would succeed and its create then ENOENT).
    // Since a lookup no longer mints empty dirs, the count is bounded by the
    // shard fan-out (<= 65536) — acceptable.
    for e in entries {
        if total_size <= size_target && count <= count_target && to_free_for_space == 0 {
            break;
        }
        if e.5 == Kind::Tmp {
            continue; // never delete an in-progress write
        }
        if remove_entry(root, &e) {
            total_size = total_size.saturating_sub(e.3);
            count = count.saturating_sub(1);
            to_free_for_space = to_free_for_space.saturating_sub(e.3);
        }
    }
}

/// Free bytes on the filesystem holding the cache (via fstatvfs on the root fd).
#[cfg(unix)]
fn avail_bytes(root: &SecureDir) -> Option<u64> {
    use std::os::unix::io::AsRawFd;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(root.as_raw_fd(), &mut st) } == 0 {
        Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
    } else {
        None
    }
}
#[cfg(not(unix))]
fn avail_bytes(_root: &SecureDir) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora::http::ResponseHeader;
    use pingora_cache::trace::Span;
    use std::path::PathBuf;

    fn meta(server_tag: &str) -> CacheMeta {
        let mut h = ResponseHeader::build(200, None).unwrap();
        h.append_header("server", server_tag.to_string()).unwrap();
        let now = SystemTime::now();
        CacheMeta::new(now + Duration::from_secs(60), now, 0, 0, h)
    }

    fn test_cache(tag: &str) -> (&'static DiskCache, PathBuf) {
        let dir0 = std::env::temp_dir().join(format!("sluice-disk-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir0);
        std::fs::create_dir_all(&dir0).unwrap();
        let dir = std::fs::canonicalize(&dir0).unwrap(); // macOS /var symlink
        let sd = Arc::new(SecureDir::provision(dir.to_str().unwrap()).unwrap());
        (Box::leak(Box::new(DiskCache::new(sd))), dir)
    }

    async fn write_entry(cache: &'static DiskCache, key: &CacheKey, m: &CacheMeta, body: &[u8]) {
        let span = Span::inactive().handle();
        let mut miss = cache.get_miss_handler(key, m, &span).await.unwrap();
        miss.write_body(Bytes::copy_from_slice(body), true)
            .await
            .unwrap();
        miss.finish().await.unwrap();
    }

    async fn read_entry(cache: &'static DiskCache, key: &CacheKey) -> Option<(CacheMeta, Vec<u8>)> {
        let span = Span::inactive().handle();
        let (m, mut hit) = cache.lookup(key, &span).await.unwrap()?;
        let mut body = Vec::new();
        while let Some(b) = hit.read_body().await.unwrap() {
            body.extend_from_slice(&b);
        }
        Some((m, body))
    }

    #[test]
    fn lookup_miss_creates_no_directories() {
        // Regression: a cache MISS used to mkdir the two shard levels, letting an
        // attacker mint unbounded empty dirs by varying the URL. A miss must
        // leave the cache root empty.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (cache, dir) = test_cache("miss");
            let before = std::fs::read_dir(&dir).unwrap().count();
            let span = Span::inactive().handle();
            for i in 0..50 {
                let key = CacheKey::new("host", format!("GET:/absent/{i}"), "");
                assert!(cache.lookup(&key, &span).await.unwrap().is_none());
            }
            let after = std::fs::read_dir(&dir).unwrap().count();
            assert_eq!(before, 0);
            assert_eq!(after, 0, "a lookup miss must not create shard directories");
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn classify_strict_tmp_and_hash_names() {
        let h = "0123456789abcdef0123456789abcdef";
        assert!(matches!(classify(&format!("{h}.ent")), Some(Kind::Entry)));
        assert!(matches!(classify(&format!("{h}.meta")), Some(Kind::Legacy)));
        assert!(matches!(classify(".tmp.123.4.5"), Some(Kind::Tmp)));
        // Foreign files (incl. a non-numeric .tmp.*) are NOT owned.
        assert!(classify(".tmp.notes").is_none());
        assert!(classify(".tmp.important").is_none());
        assert!(classify(".tmp.1.2").is_none()); // wrong arity
        assert!(classify(".tmp.a.b.c").is_none()); // non-numeric
        assert!(classify("keep.txt").is_none());
        assert!(classify("important.meta").is_none()); // non-hash stem
        assert!(classify(&format!("{}.ent", h.to_uppercase())).is_none());
    }

    #[test]
    fn reaper_never_touches_foreign_files() {
        let dir0 = std::env::temp_dir().join(format!("sluice-reap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir0);
        std::fs::create_dir_all(&dir0).unwrap();
        let dir = std::fs::canonicalize(&dir0).unwrap();
        std::fs::create_dir_all(dir.join("01").join("23")).unwrap();
        std::fs::write(dir.join("keep-1.txt"), b"important").unwrap();
        std::fs::write(dir.join(".tmp.important"), b"foreign tmp").unwrap();
        std::fs::write(dir.join("01").join("keep.dat"), b"user").unwrap();
        let h = "0123456789abcdef0123456789abcdef";
        std::fs::write(
            dir.join("01").join("23").join(format!("{h}.ent")),
            vec![0u8; 100],
        )
        .unwrap();
        let root = SecureDir::provision(dir.to_str().unwrap()).unwrap();
        reap(&root, 0, 1, 0); // aggressive — would evict everything it OWNS
        assert!(dir.join("keep-1.txt").exists(), "foreign file must survive");
        assert!(
            dir.join(".tmp.important").exists(),
            "foreign tmp must survive"
        );
        assert!(dir.join("01").join("keep.dat").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn roundtrip_and_torn_entry_is_a_miss() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (cache, dir) = test_cache("rt");
            let key = CacheKey::new("host", "GET:/x", "");
            write_entry(cache, &key, &meta("v1"), b"hello disk cache").await;
            let (m, body) = read_entry(cache, &key).await.expect("entry must hit");
            assert_eq!(body, b"hello disk cache");
            assert_eq!(m.headers().get("server").unwrap().to_str().unwrap(), "v1");

            // Truncate one byte → length check fails → miss (never a wrong body).
            let hash = key.combined();
            let ent = dir
                .join(&hash[0..2])
                .join(&hash[2..4])
                .join(entry_file(&hash));
            let data = std::fs::read(&ent).unwrap();
            std::fs::write(&ent, &data[..data.len() - 1]).unwrap();
            assert!(read_entry(cache, &key).await.is_none(), "torn entry = miss");
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn update_meta_keeps_body() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (cache, dir) = test_cache("um");
            let key = CacheKey::new("host", "GET:/y", "");
            let span = Span::inactive().handle();
            write_entry(cache, &key, &meta("v1"), b"body stays").await;
            assert!(cache.update_meta(&key, &meta("v2"), &span).await.unwrap());
            let (m, body) = read_entry(cache, &key).await.expect("still a hit");
            assert_eq!(body, b"body stays");
            assert_eq!(m.headers().get("server").unwrap().to_str().unwrap(), "v2");
            let _ = std::fs::remove_dir_all(&dir);
        });
    }
}

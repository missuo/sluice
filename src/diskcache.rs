//! Disk-backed cache storage — a production-usable `pingora_cache::Storage`.
//!
//! Cloudflare only ships an in-memory `MemCache` ("testing only, not for
//! production"); this stores each entry as ONE file under a 2-level sharded
//! directory (`<hash>.ent`):
//!
//! ```text
//! [u64 body-size][u32 internal-len][u32 header-len][internal][header][body]
//! ```
//!
//! The entry is written to a unique temp file, fsync'd, and published with a
//! SINGLE atomic rename (parent dir fsync'd after), so a crash at any point
//! leaves either the previous complete entry or none. Meta and body live in the
//! same file, so they can never disagree — the earlier two-file layout could
//! pair an old meta with a new same-length body if it crashed between its two
//! renames. The stored body-size doubles as the integrity check: a file whose
//! length doesn't equal `16 + internal + header + body` is treated as a miss.
//!
//! Streaming partial writes are not supported (`support_streaming_partial_write`
//! returns false), so a reader never sees an entry until the writer finishes.
//! A background reaper bounds the total on-disk size / file count / free space,
//! and also clears temp files and legacy two-file (`.meta`/`.body`) entries.

use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Sanity cap on the serialized meta (internal + header) length read back from
/// disk — a corrupt length field must not trigger a huge allocation.
const MAX_META_LEN: usize = 1024 * 1024;

const PREFIX_LEN: usize = 16;

fn err(ctx: &'static str) -> impl FnOnce(std::io::Error) -> Box<Error> {
    move |e| Error::because(ErrorType::InternalError, ctx, e)
}

/// An unpredictable temp name in `dir`: `.tmp.<pid>.<seq>.<nanos>`. The nanos
/// component means a local attacker who can write the shard directory can't
/// pre-create the exact name to win the create race (combined with O_EXCL
/// below, a losing race is an error, never a followed symlink).
fn tmp_in(dir: &Path) -> PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    dir.join(format!(".tmp.{}.{seq}.{nanos}", std::process::id()))
}

/// Create a fresh file with O_CREAT|O_EXCL (`create_new`): it fails rather than
/// follow a pre-planted symlink or truncate an existing file. The cache root is
/// already validated (owned, 0700, canonical) at config load, so this closes
/// the remaining shard-level symlink race.
async fn create_new(path: &Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
}

/// The 16-byte entry prefix.
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

/// fsync the directory holding `path` so a freshly renamed entry survives a
/// power loss. Best-effort by design here: a cache entry that vanishes on crash
/// is only a future miss, unlike the ACME store where durability is critical.
fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
}

pub struct DiskCache {
    root: PathBuf,
}

impl DiskCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DiskCache { root: root.into() }
    }

    /// Entry path for a key hash, sharded two directories deep.
    fn entry_path(&self, hash: &str) -> PathBuf {
        // `combined()` is a 32-char hex string, so [0..4] is always present.
        self.root
            .join(&hash[0..2])
            .join(&hash[2..4])
            .join(format!("{hash}.ent"))
    }
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

// ---- miss handler: build the whole entry in a temp, one rename on finish ----

struct DiskMiss {
    file: Option<tokio::fs::File>,
    tmp: PathBuf,
    entry_path: PathBuf,
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
        // Patch the actual body size into the prefix (written as 0 at create
        // time, before the body length was known).
        f.seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(err("disk cache seek"))?;
        f.write_all(&(self.written as u64).to_le_bytes())
            .await
            .map_err(err("disk cache stamp size"))?;
        f.sync_all().await.map_err(err("disk cache fsync"))?;
        drop(f);
        // ONE atomic publish — a reader sees the old entry or the new one,
        // never a mixed or partial state.
        tokio::fs::rename(&self.tmp, &self.entry_path)
            .await
            .map_err(err("disk cache publish"))?;
        sync_parent_dir(&self.entry_path);
        self.done = true;
        Ok(MissFinishType::Created(self.written))
    }
}

impl Drop for DiskMiss {
    fn drop(&mut self) {
        // An abandoned write (client disconnected mid-fill) leaves a temp file.
        if !self.done {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// Read and validate an entry file: returns the parsed meta and the file with
/// its cursor at the body offset. Any IO/decode/length problem → None (a miss).
async fn open_entry(path: &Path) -> Option<(CacheMeta, tokio::fs::File, u64)> {
    let mut file = tokio::fs::File::open(path).await.ok()?;
    let mut prefix = [0u8; PREFIX_LEN];
    file.read_exact(&mut prefix).await.ok()?;
    let (body_size, il, hl) = decode_prefix(&prefix);
    if il.checked_add(hl)? > MAX_META_LEN {
        return None;
    }
    let mut meta_buf = vec![0u8; il + hl];
    file.read_exact(&mut meta_buf).await.ok()?;
    let meta = CacheMeta::deserialize(&meta_buf[..il], &meta_buf[il..]).ok()?;
    // Single integrity check: the file must be exactly prefix + meta + body.
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
        let path = self.entry_path(&key.combined());
        // Any IO/parse problem is treated as a miss (robust, never fails a request).
        let Some((meta, file, body_size)) = open_entry(&path).await else {
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
        let path = self.entry_path(&key.combined());
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir)
                .await
                .map_err(err("disk cache mkdir"))?;
        }
        let (internal, header) = meta.serialize()?;
        let dir = path.parent().unwrap_or(&self.root);
        let tmp = tmp_in(dir);
        let mut file = create_new(&tmp).await.map_err(err("disk cache create"))?;
        // Body size is stamped at finish; 0 for now.
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
            tmp,
            entry_path: path,
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
        let path = self.entry_path(&key.combined());
        Ok(tokio::fs::remove_file(&path).await.is_ok())
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<bool> {
        // Rebuild the entry with the new meta and the existing body, then swap
        // it in with the same single-rename publish as a fresh write.
        let path = self.entry_path(&key.combined());
        let Some((_, mut old, _)) = open_entry(&path).await else {
            return Ok(false);
        };
        let (internal, header) = meta.serialize()?;
        let dir = path.parent().unwrap_or(&self.root).to_path_buf();
        let tmp = tmp_in(&dir);
        let res: std::result::Result<u64, std::io::Error> = async {
            let mut f = create_new(&tmp).await?;
            f.write_all(&encode_prefix(0, internal.len(), header.len()))
                .await?;
            f.write_all(&internal).await?;
            f.write_all(&header).await?;
            let copied = tokio::io::copy(&mut old, &mut f).await?;
            f.seek(std::io::SeekFrom::Start(0)).await?;
            f.write_all(&copied.to_le_bytes()).await?;
            f.sync_all().await?;
            tokio::fs::rename(&tmp, &path).await?;
            Ok(copied)
        }
        .await;
        match res {
            Ok(_) => {
                sync_parent_dir(&path);
                Ok(true)
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
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
    Tmp,    // .tmp.* — our own in-progress write (reaped only when stale)
    Legacy, // <hash>.meta / <hash>.body — retired layout, reaped on sight
}

type Entry = (PathBuf, u64, SystemTime, Kind); // (path, size, mtime, kind)

/// Every 30s, bound the cache: keep total size under `max_size`, file count under
/// `max_files` (inode-exhaustion guard), and at least `min_free` bytes free on
/// the filesystem — evicting the oldest entries when any is exceeded. Also reaps
/// temp files leaked by a hard kill and legacy two-file (`.meta`/`.body`)
/// entries from the pre-single-file layout (invisible to lookups, so they would
/// otherwise squat in the cache until size pressure evicted them). Runs in a
/// plain thread (blocking IO), and reclaims a previous run's files so the bound
/// survives restarts.
pub fn spawn_reaper(root: PathBuf, max_size: u64, max_files: u64, min_free: u64) {
    std::thread::spawn(move || loop {
        // 30s balances the enforcement window against the cost of the full
        // directory walk + sort (which grows with the file count).
        std::thread::sleep(Duration::from_secs(30));
        reap(&root, max_size, max_files, min_free);
    });
}

fn reap(root: &Path, max_size: u64, max_files: u64, min_free: u64) {
    let now = SystemTime::now();
    let mut entries: Vec<Entry> = Vec::new();
    let mut total_size: u64 = 0;
    // collect() only gathers files the cache itself owns (see `classify`); any
    // unrelated file a user left under the dir is never counted or deleted.
    collect(root, &mut entries, &mut total_size);
    entries.sort_by_key(|e| e.2); // oldest first

    // 1) Always delete leaked temp files (a hard kill left them behind; a fresh
    //    temp is an in-progress write and is kept, but still counted) and
    //    legacy-format files (unreadable by the single-file layout).
    entries.retain(|(p, sz, mtime, kind)| {
        let stale_tmp = *kind == Kind::Tmp
            && now
                .duration_since(*mtime)
                .map(|d| d > Duration::from_secs(300))
                .unwrap_or(false);
        if stale_tmp || *kind == Kind::Legacy {
            if std::fs::remove_file(p).is_ok() {
                total_size = total_size.saturating_sub(*sz);
            }
            false
        } else {
            true
        }
    });

    // 2) Evict oldest until under every bound.
    let mut count = entries.len() as u64;
    let avail = avail_bytes(root).unwrap_or(u64::MAX);
    if total_size <= max_size && count <= max_files && avail >= min_free {
        return;
    }
    // Evict to ~90% of the cap, but never below 1 — for a tiny `max-files` (e.g.
    // 5) `max_files / 10 * 9` rounds to 0, which would wipe the whole cache.
    let size_target = (max_size / 10 * 9).max(1);
    let count_target = (max_files - max_files / 10).max(1);
    let mut to_free_for_space = min_free.saturating_sub(avail);
    // If freeing the ENTIRE cache still wouldn't reach min_free, the floor is
    // unachievable (other data on the volume holds the space) — don't pointlessly
    // wipe the whole cache; just enforce the size/count caps.
    if to_free_for_space > total_size {
        to_free_for_space = 0;
    }
    for (p, sz, _, kind) in entries {
        if total_size <= size_target && count <= count_target && to_free_for_space == 0 {
            break;
        }
        if kind == Kind::Tmp {
            continue; // never delete an in-progress write
        }
        if std::fs::remove_file(&p).is_ok() {
            total_size = total_size.saturating_sub(sz);
            count = count.saturating_sub(1);
            to_free_for_space = to_free_for_space.saturating_sub(sz);
        }
    }
}

/// Is `stem` a 32-char lowercase-hex cache hash (`CacheHashKey::combined()`)?
fn is_hash_stem(stem: &str) -> bool {
    stem.len() == 32
        && stem
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Classify a filename as one the cache OWNS, or `None` for an unrelated file
/// the reaper must leave completely alone. The cache only ever creates:
/// `<32-hex>.ent` (entries), `.tmp.<pid>.<seq>.<nanos>` (its own temps), and —
/// from the retired layout — `<32-hex>.meta` / `<32-hex>.body`.
fn classify(name: &str) -> Option<Kind> {
    if name.starts_with(".tmp.") {
        return Some(Kind::Tmp);
    }
    let (stem, ext) = name.rsplit_once('.')?;
    match ext {
        "ent" if is_hash_stem(stem) => Some(Kind::Entry),
        "meta" | "body" if is_hash_stem(stem) => Some(Kind::Legacy),
        _ => None,
    }
}

fn collect(dir: &Path, out: &mut Vec<Entry>, total: &mut u64) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            collect(&p, out, total);
            continue;
        }
        // Only files the cache itself created are eligible — a user's stray
        // file (`notes.txt`, `important.meta` with a non-hash name) is ignored,
        // never counted toward the caps and never deleted.
        let name = e.file_name();
        let Some(kind) = classify(&name.to_string_lossy()) else {
            continue;
        };
        let Ok(md) = e.metadata() else { continue };
        *total += md.len();
        out.push((
            p,
            md.len(),
            md.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            kind,
        ));
    }
}

/// Free bytes on the filesystem holding `path` (via statvfs). None on failure.
#[cfg(unix)]
fn avail_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0 {
        Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
    } else {
        None
    }
}
#[cfg(not(unix))]
fn avail_bytes(_path: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora::http::ResponseHeader;
    use pingora_cache::trace::Span;

    fn meta(server_tag: &str) -> CacheMeta {
        let mut h = ResponseHeader::build(200, None).unwrap();
        h.append_header("server", server_tag.to_string()).unwrap();
        let now = SystemTime::now();
        CacheMeta::new(now + Duration::from_secs(60), now, 0, 0, h)
    }

    fn test_cache(tag: &str) -> &'static DiskCache {
        let dir = std::env::temp_dir().join(format!("sluice-disk-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Box::leak(Box::new(DiskCache::new(dir)))
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
    fn classify_only_recognizes_cache_owned_files() {
        let h = "0123456789abcdef0123456789abcdef"; // 32 hex
        assert!(matches!(classify(&format!("{h}.ent")), Some(Kind::Entry)));
        assert!(matches!(classify(&format!("{h}.meta")), Some(Kind::Legacy)));
        assert!(matches!(classify(&format!("{h}.body")), Some(Kind::Legacy)));
        assert!(matches!(classify(".tmp.123.4.5"), Some(Kind::Tmp)));
        // A user's own files are NOT owned — reaper must ignore them.
        assert!(classify("keep-1.txt").is_none());
        assert!(classify("important.meta").is_none()); // non-hash stem
        assert!(classify("notes.body").is_none());
        assert!(classify(&format!("{h}.txt")).is_none());
        assert!(classify("0123.ent").is_none()); // wrong hash length
        assert!(classify(&format!("{}.ent", h.to_uppercase())).is_none()); // uppercase
    }

    #[test]
    fn reaper_never_touches_foreign_files() {
        let dir = std::env::temp_dir().join(format!("sluice-reap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Foreign files a user might have left in (or pointed) the cache dir.
        std::fs::write(dir.join("keep-1.txt"), b"important").unwrap();
        std::fs::write(dir.join("important.meta"), b"user data").unwrap();
        let h = "0123456789abcdef0123456789abcdef";
        std::fs::write(dir.join(format!("{h}.ent")), vec![0u8; 100]).unwrap();
        // Aggressive bounds (max-files 1) would evict everything it OWNS…
        reap(&dir, 0, 1, 0);
        // …but foreign files survive untouched.
        assert_eq!(std::fs::read(dir.join("keep-1.txt")).unwrap(), b"important");
        assert_eq!(
            std::fs::read(dir.join("important.meta")).unwrap(),
            b"user data"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reaper_tiny_max_files_keeps_at_least_one() {
        let dir = std::env::temp_dir().join(format!("sluice-reap2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 6 entries, max-files 5 → count_target = 5 - 0 = 5 (NOT 0). The old
        // `max_files/10*9` rounded to 0 and wiped the whole cache.
        for i in 0..6 {
            let name = format!("{:032x}.ent", i);
            std::fs::write(dir.join(name), vec![0u8; 10]).unwrap();
        }
        reap(&dir, u64::MAX, 5, 0);
        let remaining = std::fs::read_dir(&dir).unwrap().count();
        assert!(remaining >= 4, "must not wipe the cache (kept {remaining})");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn roundtrip_and_torn_entry_is_a_miss() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let cache = test_cache("rt");
            let key = CacheKey::new("host", "GET:/x", "");
            write_entry(cache, &key, &meta("v1"), b"hello disk cache").await;
            let (m, body) = read_entry(cache, &key).await.expect("entry must hit");
            assert_eq!(body, b"hello disk cache");
            assert_eq!(m.headers().get("server").unwrap().to_str().unwrap(), "v1");

            // Corrupt the entry (truncate one byte) → the length check fails →
            // treated as a miss, never a wrong body.
            let path = cache.entry_path(&key.combined());
            let data = std::fs::read(&path).unwrap();
            std::fs::write(&path, &data[..data.len() - 1]).unwrap();
            assert!(
                read_entry(cache, &key).await.is_none(),
                "torn entry must be a miss"
            );
        });
    }

    #[test]
    fn update_meta_keeps_body() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let cache = test_cache("um");
            let key = CacheKey::new("host", "GET:/y", "");
            let span = Span::inactive().handle();
            write_entry(cache, &key, &meta("v1"), b"body stays").await;
            assert!(cache.update_meta(&key, &meta("v2"), &span).await.unwrap());
            let (m, body) = read_entry(cache, &key).await.expect("still a hit");
            assert_eq!(body, b"body stays");
            assert_eq!(m.headers().get("server").unwrap().to_str().unwrap(), "v2");
        });
    }
}

//! Disk-backed cache storage — a production-usable `pingora_cache::Storage`.
//!
//! Cloudflare only ships an in-memory `MemCache` ("testing only, not for
//! production"); this stores each entry as two files under a 2-level sharded
//! directory: `<hash>.meta` (serialized `CacheMeta`) and `<hash>.body`. Writes
//! are atomic (temp file + fsync + rename), so a crash never leaves a partial
//! entry visible. A background reaper bounds the total on-disk size (evicting
//! the oldest files), which also reclaims space left by a previous run.
//!
//! Streaming partial writes are not supported (`support_streaming_partial_write`
//! returns false), so a reader never sees an entry until the writer finishes.

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
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn err(ctx: &'static str) -> impl FnOnce(std::io::Error) -> Box<Error> {
    move |e| Error::because(ErrorType::InternalError, ctx, e)
}

/// `<path>` → `<path>.tmp.<pid>.<seq>` in the same directory (a unique temp name).
fn tmp_sibling(path: &Path) -> PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}.{}", std::process::id(), seq));
    path.with_file_name(name)
}

/// meta blob = [u32 internal-len][u32 header-len][internal][header].
fn encode_meta(internal: &[u8], header: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + internal.len() + header.len());
    out.extend_from_slice(&(internal.len() as u32).to_le_bytes());
    out.extend_from_slice(&(header.len() as u32).to_le_bytes());
    out.extend_from_slice(internal);
    out.extend_from_slice(header);
    out
}

fn decode_meta(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 8 {
        return None;
    }
    let il = u32::from_le_bytes(buf[0..4].try_into().ok()?) as usize;
    let hl = u32::from_le_bytes(buf[4..8].try_into().ok()?) as usize;
    let end = 8usize.checked_add(il)?.checked_add(hl)?;
    if buf.len() < end {
        return None;
    }
    Some((&buf[8..8 + il], &buf[8 + il..end]))
}

pub struct DiskCache {
    root: PathBuf,
}

impl DiskCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DiskCache { root: root.into() }
    }

    /// (meta, body) paths for a key hash, sharded two directories deep.
    fn paths(&self, hash: &str) -> (PathBuf, PathBuf) {
        // `combined()` is a 32-char hex string, so [0..4] is always present.
        let dir = self.root.join(&hash[0..2]).join(&hash[2..4]);
        (dir.join(format!("{hash}.meta")), dir.join(format!("{hash}.body")))
    }
}

// ---- hit handler: stream the body file out ----

struct DiskHit {
    file: tokio::fs::File,
    buf: Vec<u8>,
    weight: usize,
}

#[async_trait]
impl HandleHit for DiskHit {
    async fn read_body(&mut self) -> Result<Option<Bytes>> {
        let n = self.file.read(&mut self.buf).await.map_err(err("disk cache read"))?;
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

// ---- miss handler: write body to a temp file, publish atomically on finish ----

struct DiskMiss {
    file: Option<tokio::fs::File>,
    tmp_body: PathBuf,
    body_path: PathBuf,
    meta_path: PathBuf,
    meta_blob: Vec<u8>,
    written: usize,
    done: bool,
}

#[async_trait]
impl HandleMiss for DiskMiss {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> Result<()> {
        if let Some(f) = self.file.as_mut() {
            f.write_all(&data).await.map_err(err("disk cache write body"))?;
            self.written += data.len();
        }
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> Result<MissFinishType> {
        let mut f = self.file.take().ok_or_else(|| Error::new_str("disk cache: miss handler already finished"))?;
        f.flush().await.map_err(err("disk cache flush"))?;
        let _ = f.sync_all().await; // best-effort durability
        drop(f);
        // Publish body first, then meta — so a visible meta always has a body.
        tokio::fs::rename(&self.tmp_body, &self.body_path)
            .await
            .map_err(err("disk cache publish body"))?;
        let meta_tmp = tmp_sibling(&self.meta_path);
        tokio::fs::write(&meta_tmp, &self.meta_blob).await.map_err(err("disk cache write meta"))?;
        tokio::fs::rename(&meta_tmp, &self.meta_path).await.map_err(err("disk cache publish meta"))?;
        self.done = true;
        Ok(MissFinishType::Created(self.written))
    }
}

impl Drop for DiskMiss {
    fn drop(&mut self) {
        // An abandoned write (client disconnected mid-fill) leaves a temp file.
        if !self.done {
            let _ = std::fs::remove_file(&self.tmp_body);
        }
    }
}

#[async_trait]
impl Storage for DiskCache {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        let (meta_p, body_p) = self.paths(&key.combined());
        // Any IO/parse problem is treated as a miss (robust, never fails a request).
        let Ok(blob) = tokio::fs::read(&meta_p).await else {
            return Ok(None);
        };
        let Some((i, h)) = decode_meta(&blob) else {
            return Ok(None);
        };
        let Ok(meta) = CacheMeta::deserialize(i, h) else {
            return Ok(None);
        };
        let Ok(file) = tokio::fs::File::open(&body_p).await else {
            return Ok(None);
        };
        let weight = file.metadata().await.map(|m| m.len() as usize).unwrap_or(0);
        let hit = DiskHit { file, buf: vec![0u8; 64 * 1024], weight };
        Ok(Some((meta, Box::new(hit))))
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<MissHandler> {
        let (meta_p, body_p) = self.paths(&key.combined());
        if let Some(dir) = body_p.parent() {
            tokio::fs::create_dir_all(dir).await.map_err(err("disk cache mkdir"))?;
        }
        let (i, h) = meta.serialize()?;
        let meta_blob = encode_meta(&i, &h);
        let tmp_body = tmp_sibling(&body_p);
        let file = tokio::fs::File::create(&tmp_body).await.map_err(err("disk cache create body"))?;
        Ok(Box::new(DiskMiss {
            file: Some(file),
            tmp_body,
            body_path: body_p,
            meta_path: meta_p,
            meta_blob,
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
        let (meta_p, body_p) = self.paths(&key.combined());
        let a = tokio::fs::remove_file(&meta_p).await.is_ok();
        let b = tokio::fs::remove_file(&body_p).await.is_ok();
        Ok(a || b)
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<bool> {
        let (meta_p, _) = self.paths(&key.combined());
        let (i, h) = meta.serialize()?;
        let blob = encode_meta(&i, &h);
        let tmp = tmp_sibling(&meta_p);
        tokio::fs::write(&tmp, &blob).await.map_err(err("disk cache update meta"))?;
        tokio::fs::rename(&tmp, &meta_p).await.map_err(err("disk cache publish meta"))?;
        Ok(true)
    }

    fn support_streaming_partial_write(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

// ---- background reaper: bound total on-disk size ----

/// Every 60s, if the cache dir exceeds `max_size`, delete the oldest files until
/// it is back under ~90% of the cap. Runs in a plain thread (blocking IO). This
/// also reclaims a previous run's files, so the bound survives restarts.
pub fn spawn_reaper(root: PathBuf, max_size: u64) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(60));
        reap(&root, max_size);
    });
}

fn reap(root: &Path, max_size: u64) {
    let mut files: Vec<(PathBuf, u64, SystemTime)> = Vec::new();
    let mut total: u64 = 0;
    collect(root, &mut files, &mut total);
    if total <= max_size {
        return;
    }
    files.sort_by_key(|(_, _, mtime)| *mtime); // oldest first
    let target = (max_size / 10) * 9;
    for (p, sz, _) in files {
        if total <= target {
            break;
        }
        if std::fs::remove_file(&p).is_ok() {
            total = total.saturating_sub(sz);
        }
    }
}

fn collect(dir: &Path, out: &mut Vec<(PathBuf, u64, SystemTime)>, total: &mut u64) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            collect(&p, out, total);
        } else {
            // Skip in-progress temp writes.
            if p.to_string_lossy().contains(".tmp.") {
                continue;
            }
            if let Ok(md) = e.metadata() {
                let sz = md.len();
                *total += sz;
                out.push((p, sz, md.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
            }
        }
    }
}

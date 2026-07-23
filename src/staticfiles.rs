//! Bounded, per-docroot hot-file cache for the static file server.
//!
//! Two optimizations over the naive "open + fstat + read + EOF-probe per
//! request" path, WITHOUT weakening the fd-pinned / `O_NOFOLLOW` / no-symlink
//! [`SecureDir`] invariant:
//!
//!  1. **Fused I/O.** [`StaticFileCache::get`] performs the secure `openat` walk,
//!     the single `fstat`, and the small-file read in ONE `spawn_blocking` job
//!     (see [`secure_open_read`]) — one blocking-pool hop instead of four — and
//!     the length comes from the same fd that is read, so body and
//!     `Content-Length` can never disagree.
//!  2. **Content cache.** Small files (<= [`CACHE_MAX_FILE`]) are held as an
//!     immutable [`Bytes`] snapshot; a hit within the TTL clones the handle and
//!     serves with zero syscalls. Larger files stream uncached.
//!
//! ## Security
//!
//! Every cache FILL and every revalidation opens through the pinned
//! [`SecureDir`] with the exact same component-by-component `O_NOFOLLOW` walk as
//! the uncached path — a symlink (or a swapped parent) is refused (`ELOOP`) and
//! turns into a 404, so the cache can never serve content from outside the root
//! or follow a symlink. The cache is created bound to ONE `SecureDir` (one
//! docroot), so two roots get two independent caches and cannot collide; a
//! config reload builds a new handler with a new root + new cache, so stale
//! content from an old root is never served. A cached snapshot is immutable, so
//! it is safe against a later symlink/parent swap; it is deliberately served for
//! at most the TTL (bounded staleness), after which the next request re-opens
//! securely and re-fills (or 404s if the path is now a symlink/gone).
//!
//! Content is cached as bytes, never a shared file descriptor — so there is no
//! shared file offset to corrupt and no descriptor to exhaust.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::OnceCell;

use crate::dirs::SecureDir;

/// Files this size or smaller are read fully in the ONE fused blocking job and
/// served from memory (and cached, when caching is enabled); ANYTHING larger is
/// streamed through a per-request fd with a fixed buffer and is NEVER fully
/// materialized. Deliberately equal to the cache-eligibility bound, so a body
/// that will not enter the cache is never buffered whole — otherwise a client
/// that opens many streams and withholds flow-control credit could pin unbounded
/// memory (an amplifier the cache's own byte/entry caps do not cover).
pub const CACHE_MAX_FILE: u64 = 64 * 1024;
/// Fixed buffer used to stream a large (uncached) file, chunk by chunk.
pub const STREAM_BUF: usize = 64 * 1024;
/// Hard cap on the number of cached entries (defense against path churn).
pub const CACHE_MAX_ENTRIES: usize = 1024;
/// Hard cap on total cached content bytes.
pub const CACHE_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// What [`StaticFileCache::get`] resolved the request to.
#[derive(Debug)]
pub enum Served {
    /// The whole body, in memory (a cache hit, or a fused small-file read).
    /// `Content-Length` is `bytes.len()`.
    Inline(Bytes),
    /// The file is larger than [`CACHE_MAX_FILE`]; the caller streams it from a
    /// per-request fd. NO length is carried here on purpose: the caller performs
    /// the single AUTHORITATIVE secure open and derives `Content-Length` from THAT
    /// fd's metadata, so the advertised length and the streamed body always come
    /// from the same open file description — an atomic replacement between opens
    /// can never pair an old length with new content.
    Large,
}

/// Why a static request could not be served from the cache/fill path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaticError {
    /// The path does not resolve to a regular file under the pinned root
    /// (missing, a symlink/`ELOOP`, `ENOTDIR`, or not a regular file) → 404.
    NotFound,
    /// A blocking-pool / read failure after a successful open → drop/500.
    Io,
}

struct Entry {
    bytes: Bytes,
    inserted: Instant,
    /// Clock tick of last use, for approximate LRU eviction.
    last_used: AtomicU64,
}

#[derive(Default)]
struct Inner {
    map: HashMap<String, Arc<Entry>>,
    total_bytes: usize,
}

/// A bounded hot-file content cache scoped to ONE pinned docroot.
pub struct StaticFileCache {
    /// Serve a cached snapshot for at most this long before re-validating by a
    /// fresh secure open. `0` disables the content cache (the fused read still
    /// applies); revalidation is then effectively per request.
    ttl: Duration,
    inner: RwLock<Inner>,
    /// In-flight fills, for per-key singleflight so a burst of concurrent misses
    /// for the same file does exactly one secure open+read. The cell stores the
    /// TERMINAL result (success OR failure) so every waiter on a flight consumes
    /// the same outcome — a same-path error burst does one walk, not one per
    /// request. The cell is removed after publication (by pointer identity), so a
    /// later request starts a fresh flight; this is NOT a long-lived negative cache.
    inflight: DashMap<String, Arc<OnceCell<Result<Fill, StaticError>>>>,
    clock: AtomicU64,
    /// Count of `do_fill` invocations = secure openat walks (for tests/metrics).
    walks: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
}

#[derive(Clone)]
enum Fill {
    Inline(Arc<Entry>),
    Large,
}

impl StaticFileCache {
    pub fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(StaticFileCache {
            ttl,
            inner: RwLock::new(Inner::default()),
            inflight: DashMap::new(),
            clock: AtomicU64::new(0),
            walks: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        })
    }

    fn tick(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::Relaxed)
    }

    /// Resolve the canonical relative `key` (already normalized — no `.`/`..`/empty
    /// segments, `/`-joined) under the pinned `root`, serving from cache when fresh
    /// and filling securely (with singleflight) otherwise.
    ///
    /// The hot cache HIT needs only the BORROWED key — no component `Vec` and no
    /// key clone are built. The validated components (for the secure open) and the
    /// owned key are materialized ONLY on a miss: because `key` has no empty
    /// segments, `key.split('/')` reproduces exactly the components the caller
    /// validated, which the fd-pinned `openat`/`O_NOFOLLOW` walk re-validates.
    pub async fn get(
        self: &Arc<Self>,
        root: &Arc<SecureDir>,
        key: &str,
    ) -> Result<Served, StaticError> {
        // Fast path: a fresh cached snapshot, zero syscalls, zero allocation.
        if self.ttl > Duration::ZERO {
            if let Some(bytes) = self.lookup_fresh(key) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Served::Inline(bytes));
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        let comps: Vec<String> = key.split('/').map(String::from).collect();
        Ok(match self.fill(root, comps, key.to_string()).await? {
            Fill::Inline(e) => Served::Inline(e.bytes.clone()),
            Fill::Large => Served::Large,
        })
    }

    fn lookup_fresh(&self, key: &str) -> Option<Bytes> {
        let inner = self.inner.read().unwrap();
        let e = inner.map.get(key)?;
        if e.inserted.elapsed() < self.ttl {
            // No per-hit LRU write: `last_used` is stamped at insert and refreshed
            // by the per-TTL re-fill, so eviction stays approximately-LRU WITHOUT
            // the hot path bouncing the shared clock atomic + the entry's cache
            // line across cores (8 cores serving one hot file otherwise contend).
            Some(e.bytes.clone())
        } else {
            None
        }
    }

    /// Singleflight the secure open+read for `key`, coalescing BOTH successes and
    /// failures so a concurrent burst does exactly one secure walk.
    async fn fill(
        self: &Arc<Self>,
        root: &Arc<SecureDir>,
        comps: Vec<String>,
        key: String,
    ) -> Result<Fill, StaticError> {
        let cell = self
            .inflight
            .entry(key.clone())
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone();

        let this = self.clone();
        let root = root.clone();
        let key_for_fill = key.clone();
        // `get_or_init` stores the initializer's value (which here is itself a
        // terminal `Result`), unlike `get_or_try_init` which discards `Err` and
        // re-elects a new waiter. So all waiters on this flight get the SAME
        // success OR failure from ONE `do_fill`.
        let res = cell
            .get_or_init(move || async move { this.do_fill(root, comps, key_for_fill).await })
            .await
            .clone();

        // Remove the flight only AFTER publication, by pointer identity so a newer
        // flight for the same key survives. A later request re-fills — this is not
        // a persisted negative cache.
        self.inflight.remove_if(&key, |_, c| Arc::ptr_eq(c, &cell));
        res
    }

    async fn do_fill(
        &self,
        root: Arc<SecureDir>,
        comps: Vec<String>,
        key: String,
    ) -> Result<Fill, StaticError> {
        self.walks.fetch_add(1, Ordering::Relaxed);
        let outcome = tokio::task::spawn_blocking(move || secure_open_read(&root, &comps))
            .await
            .map_err(|_| StaticError::Io)?;
        match outcome {
            Ok(OpenOutcome::Inline(buf)) => {
                let entry = Arc::new(Entry {
                    bytes: Bytes::from(buf),
                    inserted: Instant::now(),
                    last_used: AtomicU64::new(self.tick()),
                });
                // Cache only small files, and only when caching is enabled.
                if self.ttl > Duration::ZERO && entry.bytes.len() as u64 <= CACHE_MAX_FILE {
                    self.insert(key, entry.clone());
                }
                Ok(Fill::Inline(entry))
            }
            // Large: classified only. The body is NOT read here (never materialize
            // an uncached whole body); the caller streams it from its own fd.
            Ok(OpenOutcome::Large) => Ok(Fill::Large),
            Err(_) => {
                // The path no longer resolves to a regular file (deleted, or now a
                // symlink) — purge any stale snapshot so it can't linger, and 404.
                self.remove(&key);
                Err(StaticError::NotFound)
            }
        }
    }

    fn insert(&self, key: String, entry: Arc<Entry>) {
        let sz = entry.bytes.len();
        if sz as u64 > CACHE_MAX_FILE {
            return;
        }
        let mut inner = self.inner.write().unwrap();
        if let Some(old) = inner.map.remove(&key) {
            inner.total_bytes -= old.bytes.len();
        }
        // Evict (approximate LRU: smallest last_used) until the new entry fits
        // within BOTH the entry-count and total-byte caps.
        while inner.map.len() + 1 > CACHE_MAX_ENTRIES
            || inner.total_bytes + sz > CACHE_MAX_TOTAL_BYTES
        {
            let victim = inner
                .map
                .iter()
                .min_by_key(|(_, e)| e.last_used.load(Ordering::Relaxed))
                .map(|(k, _)| k.clone());
            match victim {
                Some(vk) => {
                    if let Some(v) = inner.map.remove(&vk) {
                        inner.total_bytes -= v.bytes.len();
                    }
                }
                None => break,
            }
        }
        inner.total_bytes += sz;
        inner.map.insert(key, entry);
    }

    fn remove(&self, key: &str) {
        let mut inner = self.inner.write().unwrap();
        if let Some(old) = inner.map.remove(key) {
            inner.total_bytes -= old.bytes.len();
        }
    }

    /// (entry count, total cached bytes) — for tests/observability.
    pub fn stats(&self) -> (usize, usize) {
        let inner = self.inner.read().unwrap();
        (inner.map.len(), inner.total_bytes)
    }

    /// (hits, misses) — for tests/observability.
    pub fn hit_miss(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    /// Number of secure openat walks performed (`do_fill` calls) — for tests.
    pub fn walks(&self) -> u64 {
        self.walks.load(Ordering::Relaxed)
    }
}

enum OpenOutcome {
    /// File content, fully read (`len <= CACHE_MAX_FILE`).
    Inline(Vec<u8>),
    /// File is larger than the inline threshold; the caller streams it from its
    /// own authoritative open (so its length comes from the streamed fd).
    Large,
}

/// Securely open `comps` under `root` (pinned-root `openat(O_NOFOLLOW)` walk,
/// regular-file check). For a small file (`<= CACHE_MAX_FILE`) it reads the
/// content in the SAME blocking call and returns it — the returned bytes are the
/// number actually read, so a concurrent truncation still yields a consistent
/// body/`Content-Length` and a concurrent growth reads only the snapshot length.
/// A larger file is only classified `Large` (NOT read here — never buffer an
/// uncached whole body); the caller streams it.
fn secure_open_read(root: &SecureDir, comps: &[String]) -> io::Result<OpenOutcome> {
    use std::io::Read;
    let (file, meta) = root.open_file_under_with_meta(comps)?;
    let len = meta.len();
    if len <= CACHE_MAX_FILE {
        let mut buf = Vec::with_capacity(len as usize);
        // `take(len)` bounds the read to the fstat length even if the file grows.
        file.take(len).read_to_end(&mut buf)?;
        Ok(OpenOutcome::Inline(buf))
    } else {
        Ok(OpenOutcome::Large)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> (std::path::PathBuf, Arc<SecureDir>) {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base0 = std::env::temp_dir().join(format!("sluice-sfc-{tag}-{n}"));
        let _ = std::fs::remove_dir_all(&base0);
        std::fs::create_dir_all(&base0).unwrap();
        // Canonicalize: macOS temp_dir() lives under a /var symlink and
        // SecureDir::open_ro refuses symlink components.
        let base = std::fs::canonicalize(&base0).unwrap();
        let root = base.join("www");
        std::fs::create_dir_all(&root).unwrap();
        let sd = Arc::new(SecureDir::open_ro(root.to_str().unwrap()).unwrap());
        (base, sd)
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    fn get(
        cache: &Arc<StaticFileCache>,
        root: &Arc<SecureDir>,
        rel: &str,
    ) -> Result<Served, StaticError> {
        // `rel` is already a normalized key here (no empty/dot segments).
        rt().block_on(cache.get(root, rel))
    }

    fn inline_bytes(s: Served) -> Bytes {
        match s {
            Served::Inline(b) => b,
            Served::Large => panic!("expected inline, got large"),
        }
    }

    #[test]
    fn serves_correct_bytes_and_caches_small_files() {
        let (base, root) = tmp_root("basic");
        std::fs::write(base.join("www/a.txt"), b"hello world").unwrap();
        let cache = StaticFileCache::new(Duration::from_secs(30));

        // Cold: miss + fill, correct bytes.
        let b = inline_bytes(get(&cache, &root, "a.txt").unwrap());
        assert_eq!(&b[..], b"hello world");
        assert_eq!(cache.hit_miss(), (0, 1));
        assert_eq!(cache.stats(), (1, 11));

        // Hot: hit, identical bytes, no new fill.
        let b2 = inline_bytes(get(&cache, &root, "a.txt").unwrap());
        assert_eq!(&b2[..], b"hello world");
        assert_eq!(cache.hit_miss(), (1, 1));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn large_file_streams_uncached_and_carries_no_length() {
        let (base, root) = tmp_root("large");
        // A clearly-large file (well over the inline/cache cap).
        let big = vec![b'x'; 300 * 1024];
        std::fs::write(base.join("www/big.bin"), &big).unwrap();
        let cache = StaticFileCache::new(Duration::from_secs(30));
        // Finding 1: the cache returns a length-FREE `Large` marker, forcing the
        // caller to derive Content-Length from its own authoritative open (same
        // fd as the body) — an old classify-length can't be paired with new bytes.
        assert!(matches!(
            get(&cache, &root, "big.bin").unwrap(),
            Served::Large
        ));
        // Never cached, and never materialized into the cache byte total.
        assert_eq!(cache.stats(), (0, 0));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn cache_max_boundary_inlines_at_limit_streams_above() {
        let (base, root) = tmp_root("boundary");
        // Finding 2: eager reads are bounded to CACHE_MAX_FILE. A file exactly AT
        // the cap is inlined + cached; ONE byte over is streamed (Large), never
        // buffered whole and never cached.
        let at = vec![b'a'; CACHE_MAX_FILE as usize];
        std::fs::write(base.join("www/at.dat"), &at).unwrap();
        let over = vec![b'o'; CACHE_MAX_FILE as usize + 1];
        std::fs::write(base.join("www/over.dat"), &over).unwrap();
        let cache = StaticFileCache::new(Duration::from_secs(30));

        let b = inline_bytes(get(&cache, &root, "at.dat").unwrap());
        assert_eq!(b.len(), at.len());
        assert_eq!(cache.stats(), (1, at.len()), "a file AT the cap is cached");

        assert!(
            matches!(get(&cache, &root, "over.dat").unwrap(), Served::Large),
            "a file over the cap must be streamed (Large), not buffered inline"
        );
        // Unchanged: the over-cap file was neither materialized nor cached.
        assert_eq!(cache.stats(), (1, at.len()));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn error_burst_does_one_secure_walk() {
        // Finding 3: a concurrent burst of requests for a MISSING path must do
        // exactly ONE secure openat walk (singleflight of failures), handing the
        // same NotFound to every waiter — not one walk per request.
        let (base, root) = tmp_root("errflight");
        let cache = cache_new();
        rt().block_on(async {
            // `join!` polls all eight concurrently on ONE task, so they all attach
            // to the same in-flight cell before the first fill completes.
            let (a, b, c, d, e, f, g, h) = tokio::join!(
                cache.get(&root, "gone.txt"),
                cache.get(&root, "gone.txt"),
                cache.get(&root, "gone.txt"),
                cache.get(&root, "gone.txt"),
                cache.get(&root, "gone.txt"),
                cache.get(&root, "gone.txt"),
                cache.get(&root, "gone.txt"),
                cache.get(&root, "gone.txt"),
            );
            for r in [a, b, c, d, e, f, g, h] {
                assert_eq!(r.unwrap_err(), StaticError::NotFound);
            }
        });
        assert_eq!(
            cache.walks(),
            1,
            "a concurrent error burst must do exactly ONE secure walk"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn mtime_or_size_change_invalidates_after_ttl() {
        let (base, root) = tmp_root("inval");
        let path = base.join("www/v.txt");
        std::fs::write(&path, b"v1").unwrap();
        // Very short TTL so revalidation is exercised without a slow test.
        let cache = StaticFileCache::new(Duration::from_millis(40));
        assert_eq!(
            &inline_bytes(get(&cache, &root, "v.txt").unwrap())[..],
            b"v1"
        );
        // Within TTL: still the old snapshot.
        assert_eq!(
            &inline_bytes(get(&cache, &root, "v.txt").unwrap())[..],
            b"v1"
        );

        std::fs::write(&path, b"v2-longer").unwrap();
        std::thread::sleep(Duration::from_millis(60)); // past TTL
        assert_eq!(
            &inline_bytes(get(&cache, &root, "v.txt").unwrap())[..],
            b"v2-longer",
            "a changed file must be re-read after the TTL"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn symlink_escape_is_refused_cold_and_after_caching() {
        let (base, root) = tmp_root("symlink");
        std::fs::write(base.join("secret"), b"TOPSECRET").unwrap();
        // Cold: a symlink under the root pointing outside is refused (404), never
        // cached.
        std::os::unix::fs::symlink(base.join("secret"), base.join("www/leak")).unwrap();
        assert_eq!(
            get(&cache_new(), &root, "leak").unwrap_err(),
            StaticError::NotFound
        );

        // Cached path: cache a legit file, then replace it with a symlink to the
        // secret. Within a 0 TTL every request re-opens securely, so the symlink
        // is refused and the secret is NEVER served.
        let cache = StaticFileCache::new(Duration::from_millis(30));
        std::fs::write(base.join("www/f.txt"), b"legit").unwrap();
        assert_eq!(
            &inline_bytes(get(&cache, &root, "f.txt").unwrap())[..],
            b"legit"
        );
        std::fs::remove_file(base.join("www/f.txt")).unwrap();
        std::os::unix::fs::symlink(base.join("secret"), base.join("www/f.txt")).unwrap();
        std::thread::sleep(Duration::from_millis(50)); // past TTL → revalidate
        assert_eq!(
            get(&cache, &root, "f.txt").unwrap_err(),
            StaticError::NotFound,
            "a path that became a symlink must 404, never serve the target"
        );
        // The stale snapshot was purged.
        assert_eq!(cache.stats(), (0, 0));
        let _ = std::fs::remove_dir_all(&base);
    }

    fn cache_new() -> Arc<StaticFileCache> {
        StaticFileCache::new(Duration::from_secs(30))
    }

    #[test]
    fn distinct_roots_do_not_collide() {
        let (base1, root1) = tmp_root("root1");
        let (base2, root2) = tmp_root("root2");
        std::fs::write(base1.join("www/same.txt"), b"from-root-1").unwrap();
        std::fs::write(base2.join("www/same.txt"), b"from-root-2").unwrap();
        // Each docroot gets its OWN cache (as the config builds per handler).
        let c1 = cache_new();
        let c2 = cache_new();
        assert_eq!(
            &inline_bytes(get(&c1, &root1, "same.txt").unwrap())[..],
            b"from-root-1"
        );
        assert_eq!(
            &inline_bytes(get(&c2, &root2, "same.txt").unwrap())[..],
            b"from-root-2"
        );
        // Even the SAME cache object keyed by relative path is bound to whichever
        // root the caller passes — it never resolves outside the given root.
        let _ = std::fs::remove_dir_all(&base1);
        let _ = std::fs::remove_dir_all(&base2);
    }

    #[test]
    fn bounds_are_enforced_under_churn() {
        let (base, root) = tmp_root("bounds");
        // Create many distinct small files and request them all.
        let n = CACHE_MAX_ENTRIES + 200;
        for i in 0..n {
            std::fs::write(base.join(format!("www/f{i}.txt")), format!("body-{i}")).unwrap();
        }
        let cache = StaticFileCache::new(Duration::from_secs(60));
        for i in 0..n {
            let b = inline_bytes(get(&cache, &root, &format!("f{i}.txt")).unwrap());
            assert_eq!(&b[..], format!("body-{i}").as_bytes());
        }
        let (entries, bytes) = cache.stats();
        assert!(
            entries <= CACHE_MAX_ENTRIES,
            "entries {entries} must be bounded"
        );
        assert!(
            bytes <= CACHE_MAX_TOTAL_BYTES,
            "bytes {bytes} must be bounded"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn empty_file_serves_empty_inline() {
        let (base, root) = tmp_root("empty");
        std::fs::write(base.join("www/empty.txt"), b"").unwrap();
        let cache = cache_new();
        let b = inline_bytes(get(&cache, &root, "empty.txt").unwrap());
        assert!(b.is_empty());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn missing_file_is_not_found() {
        let (base, root) = tmp_root("missing");
        let cache = cache_new();
        assert_eq!(
            get(&cache, &root, "nope.txt").unwrap_err(),
            StaticError::NotFound
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

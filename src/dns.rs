//! TTL-aware upstream DNS cache with singleflight coalescing, bounded resolver
//! concurrency, and serve-stale-while-revalidate.
//!
//! Why this exists (round-21/22): resolving an upstream hostname per request
//! through `tokio::net::lookup_host` wraps blocking `getaddrinfo` in
//! `spawn_blocking`, which Tokio cannot abort. Under a slow/broken/malicious
//! resolver, a request flood would start hundreds of un-cancellable blocking jobs
//! (the outer timeout frees the client with a 502 but the OS job runs on) and
//! re-resolve on every request, so a DNS outage also took healthy *pooled* upstream
//! connectivity out of service. This cache fixes that:
//!
//! * **TTL cache** — within the fresh window the resolver is never consulted, so a
//!   hot path reuses the answer (and the upstream connection pool) with no DNS.
//! * **Singleflight (success AND failure)** — concurrent lookups for one name
//!   coalesce onto ONE in-flight resolve. The leader publishes its terminal result
//!   (a success set OR a negative/backoff marker) to the shared cache entry; every
//!   waiter, after acquiring the flight lock, honors that published result and
//!   returns WITHOUT re-resolving. A cancelled/panicking leader releases the RAII
//!   flight lock, so exactly one waiter re-elects itself rather than all of them.
//! * **Bounded concurrency that actually bounds `getaddrinfo`** — the system
//!   resolver moves an `OwnedSemaphorePermit` INTO the `spawn_blocking` closure, so
//!   the permit is held until the OS call truly returns even if the awaiting future
//!   timed out; a flood therefore cannot exceed the configured number of concurrent
//!   blocking jobs.
//! * **One absolute deadline** — the flight-lock wait, the semaphore wait, and the
//!   resolver op share a single deadline, so `upstream-dns-timeout-secs` is a TOTAL
//!   bound, not a per-step one.
//! * **Serve-stale-while-revalidate** — on TTL expiry the last-known-good answer is
//!   returned immediately and one background refresh runs; a transient DNS outage
//!   keeps healthy pools alive for a bounded stale window.
//!
//! The resolver is pluggable so behavior is deterministically unit-testable
//! without touching the system resolver.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

/// A pluggable name resolver: `(host, port, permit) -> addresses`. The caller has
/// already acquired a concurrency `permit`; the resolver MUST keep it alive until
/// its underlying (possibly non-cancellable) work truly completes — the system
/// resolver moves it into `spawn_blocking` — so the concurrency bound holds even
/// when the awaiting future is dropped on timeout.
pub type Resolver = Arc<
    dyn Fn(
            String,
            u16,
            OwnedSemaphorePermit,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
        + Send
        + Sync,
>;

struct Entry {
    /// Last-known-good answer (empty = a failure with no prior good answer).
    addrs: Vec<SocketAddr>,
    /// Do NOT consult the resolver again before this instant. Set to `now + ttl`
    /// on success and `now + backoff` on failure (a backoff that bounds the
    /// re-resolution rate under a persistent outage).
    revalidate_at: Instant,
    /// Serve `addrs` (fresh OR stale) until this instant. Set to `now + ttl + stale`
    /// on success; left unchanged on failure so the stale window is measured from
    /// the last successful resolve.
    good_until: Instant,
}

/// The timing policy for one resolve: how long the resolver may not be re-consulted
/// after a failure (`backoff`), the fresh TTL, and the extra stale-serve window.
#[derive(Clone, Copy)]
struct Policy {
    backoff: Duration,
    ttl: Duration,
    stale: Duration,
}

struct Inner {
    entries: DashMap<String, Entry>,
    /// Per-key singleflight lock: concurrent resolves for one name coalesce.
    inflight: DashMap<String, Arc<Mutex<()>>>,
    /// Global bound on concurrent (blocking) resolver jobs.
    sema: Arc<Semaphore>,
    resolver: Resolver,
    max_entries: usize,
}

/// A cheaply-clonable handle to the shared DNS cache.
#[derive(Clone)]
pub struct DnsCache(Arc<Inner>);

fn negative_cached_error() -> std::io::Error {
    std::io::Error::other("dns: negative-cached (resolver backoff)")
}

impl DnsCache {
    /// Build a cache with an explicit resolver (used by tests).
    pub fn new(max_concurrent: usize, max_entries: usize, resolver: Resolver) -> Self {
        DnsCache(Arc::new(Inner {
            entries: DashMap::new(),
            inflight: DashMap::new(),
            sema: Arc::new(Semaphore::new(max_concurrent.max(1))),
            resolver,
            max_entries: max_entries.max(1),
        }))
    }

    /// Build a cache backed by the system resolver (`getaddrinfo` via
    /// `spawn_blocking`), with the concurrency permit MOVED into the blocking job.
    pub fn with_system_resolver(max_concurrent: usize, max_entries: usize) -> Self {
        let resolver: Resolver =
            Arc::new(|host: String, port: u16, permit: OwnedSemaphorePermit| {
                Box::pin(async move {
                    let handle = tokio::task::spawn_blocking(move || {
                        // The permit lives until `getaddrinfo` RETURNS — even if the
                        // awaiter below is dropped on timeout — so the semaphore bounds
                        // the real blocking-job count, not just the async wrappers.
                        let _permit = permit;
                        use std::net::ToSocketAddrs;
                        (host.as_str(), port)
                            .to_socket_addrs()
                            .map(|it| it.collect::<Vec<_>>())
                    });
                    match handle.await {
                        Ok(r) => r,
                        Err(e) => Err(std::io::Error::other(format!(
                            "dns: blocking join error: {e}"
                        ))),
                    }
                })
            });
        Self::new(max_concurrent, max_entries, resolver)
    }

    /// Resolve `host:port` to its non-empty address set.
    ///
    /// An IP literal bypasses DNS and the cache. A fresh cache hit returns
    /// immediately with no resolver call; a fresh negative entry returns a cached
    /// error without resolving. On TTL expiry the last-known-good answer is served
    /// and a single background refresh is triggered. Otherwise the name is resolved
    /// in the foreground (coalesced by singleflight, bounded by the semaphore, under
    /// one total deadline). On failure/timeout/empty a still-valid stale answer is
    /// served; if none exists an `Err` is returned for the caller to map to a 502.
    pub async fn resolve(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
        ttl: Duration,
        stale: Duration,
    ) -> std::io::Result<Vec<SocketAddr>> {
        // IP literals never touch DNS or the cache.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let key = format!("{host}:{port}");
        let now = Instant::now();
        if let Some(e) = self.0.entries.get(&key) {
            if now < e.revalidate_at {
                // Within the do-not-resolve window (fresh TTL, or a failure backoff).
                if !e.addrs.is_empty() && now < e.good_until {
                    return Ok(e.addrs.clone());
                }
                // Negative-cached (recent failure, nothing serveable): fail fast.
                return Err(negative_cached_error());
            }
            // TTL expired: serve the last-known-good answer NOW and refresh in the
            // background, so request latency and pooled connectivity don't depend on
            // a slow resolver.
            if !e.addrs.is_empty() && now < e.good_until {
                let stale_addrs = e.addrs.clone();
                drop(e);
                self.spawn_refresh(host.to_string(), port, key, timeout, ttl, stale);
                return Ok(stale_addrs);
            }
            drop(e);
        }
        // No entry, or expired past the stale window: resolve in the foreground under
        // a single absolute deadline. `backoff` == `timeout` bounds the re-resolution
        // rate after a failure.
        let deadline = now + timeout;
        let policy = Policy {
            backoff: timeout,
            ttl,
            stale,
        };
        self.resolve_foreground(host, port, &key, deadline, policy)
            .await
    }

    /// Foreground resolve for one name, coalesced via the per-key singleflight lock.
    /// The flight-lock wait, semaphore wait, and resolver op share `deadline`.
    async fn resolve_foreground(
        &self,
        host: &str,
        port: u16,
        key: &str,
        deadline: Instant,
        policy: Policy,
    ) -> std::io::Result<Vec<SocketAddr>> {
        let lock = self.flight_lock(key);
        // Wait for the flight lock, but never past the total deadline.
        let budget = deadline.saturating_duration_since(Instant::now());
        let _flight = match tokio::time::timeout(budget, lock.lock()).await {
            Ok(g) => g,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "dns: timed out waiting for in-flight resolve",
                ));
            }
        };
        // Re-check under the flight lock: a prior/concurrent leader may have PUBLISHED
        // a terminal result — a success set OR a negative/backoff marker. Honor BOTH
        // so waiters coalesce onto the leader instead of re-resolving.
        if let Some(answer) = self.cached_answer(key) {
            return answer;
        }
        // We are the leader. Resolve with the REMAINING budget, then ALWAYS publish a
        // terminal result so waiters coalesce.
        let remaining = deadline.saturating_duration_since(Instant::now());
        let result = self.do_resolve(host, port, remaining).await;
        match result {
            Ok(addrs) if !addrs.is_empty() => {
                self.store_success(key, addrs.clone(), policy.ttl, policy.stale);
                Ok(addrs)
            }
            other => {
                self.store_failure(key, policy.backoff);
                // Serve stale last-known-good if still within the stale window.
                if let Some(e) = self.0.entries.get(key) {
                    if !e.addrs.is_empty() && Instant::now() < e.good_until {
                        return Ok(e.addrs.clone());
                    }
                }
                Err(match other {
                    Ok(_) => std::io::Error::other("dns: resolver returned no addresses"),
                    Err(e) => e,
                })
            }
        }
    }

    /// If the cache holds a still-authoritative answer for `key`, return it (a
    /// success set, or a cached error for a negative/backoff entry); else `None`
    /// (the caller must resolve).
    fn cached_answer(&self, key: &str) -> Option<std::io::Result<Vec<SocketAddr>>> {
        let e = self.0.entries.get(key)?;
        let now = Instant::now();
        if now < e.revalidate_at {
            if !e.addrs.is_empty() && now < e.good_until {
                return Some(Ok(e.addrs.clone()));
            }
            return Some(Err(negative_cached_error()));
        }
        // TTL expired but still serveable as stale (a concurrent refresh may pick up).
        if !e.addrs.is_empty() && now < e.good_until {
            return Some(Ok(e.addrs.clone()));
        }
        None
    }

    /// The bounded, timed resolve. Acquires an OWNED semaphore permit (moved into the
    /// resolver's blocking job) and applies `budget` across BOTH the semaphore wait
    /// and the resolver op.
    async fn do_resolve(
        &self,
        host: &str,
        port: u16,
        budget: Duration,
    ) -> std::io::Result<Vec<SocketAddr>> {
        let deadline = Instant::now() + budget;
        let permit = match tokio::time::timeout(budget, self.0.sema.clone().acquire_owned()).await {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return Err(std::io::Error::other("dns: semaphore closed")),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "dns: timed out waiting for a resolver slot",
                ));
            }
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        let fut = (self.0.resolver)(host.to_string(), port, permit);
        match tokio::time::timeout(remaining, fut).await {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "dns: resolve timed out",
            )),
        }
    }

    /// Trigger ONE background refresh for `key` (coalesced: if a flight is already
    /// running for this name, skip). Keeps request latency independent of the
    /// resolver on TTL expiry.
    fn spawn_refresh(
        &self,
        host: String,
        port: u16,
        key: String,
        timeout: Duration,
        ttl: Duration,
        stale: Duration,
    ) {
        let cache = self.clone();
        tokio::spawn(async move {
            let lock = cache.flight_lock(&key);
            // Non-blocking singleflight: if another flight holds the lock, a refresh
            // (or a foreground resolve) is already in progress — do nothing.
            let Ok(_flight) = lock.try_lock() else {
                return;
            };
            // Another flight may have completed between our TTL check and here.
            if let Some(e) = cache.0.entries.get(&key) {
                if Instant::now() < e.revalidate_at {
                    return;
                }
            }
            match cache.do_resolve(&host, port, timeout).await {
                Ok(addrs) if !addrs.is_empty() => cache.store_success(&key, addrs, ttl, stale),
                _ => cache.store_failure(&key, timeout),
            }
        });
    }

    fn flight_lock(&self, key: &str) -> Arc<Mutex<()>> {
        self.0
            .inflight
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn store_success(&self, key: &str, addrs: Vec<SocketAddr>, ttl: Duration, stale: Duration) {
        let now = Instant::now();
        self.evict_if_full(key);
        self.0.entries.insert(
            key.to_string(),
            Entry {
                addrs,
                revalidate_at: now + ttl,
                good_until: now + ttl + stale,
            },
        );
    }

    fn store_failure(&self, key: &str, backoff: Duration) {
        let now = Instant::now();
        // Keep the last-known-good answer + its stale window; just back off the
        // resolver so we don't re-resolve every request during an outage.
        if let Some(mut e) = self.0.entries.get_mut(key) {
            e.revalidate_at = now + backoff;
            return;
        }
        // No prior answer: negative-cache with a backoff so a first-resolve failure
        // doesn't turn into a per-request resolver storm.
        self.evict_if_full(key);
        self.0.entries.insert(
            key.to_string(),
            Entry {
                addrs: Vec::new(),
                revalidate_at: now + backoff,
                good_until: now,
            },
        );
    }

    fn evict_if_full(&self, key: &str) {
        if !self.0.entries.contains_key(key) && self.0.entries.len() >= self.0.max_entries {
            // Bounded size: drop one entry to make room. Keys are bounded by the
            // configured upstream set, so this is a defensive backstop.
            if let Some(victim) = self.0.entries.iter().next().map(|r| r.key().clone()) {
                self.0.entries.remove(&victim);
            }
        }
    }

    /// Seed a fresh successful cache entry, bypassing the resolver. Intended for
    /// tests / deterministic seeding; never called on the request path.
    pub fn seed(
        &self,
        host: &str,
        port: u16,
        addrs: Vec<SocketAddr>,
        ttl: Duration,
        stale: Duration,
    ) {
        self.store_success(&format!("{host}:{port}"), addrs, ttl, stale);
    }

    /// Seed a long-lived NEGATIVE (backoff) entry so `resolve` returns a bounded
    /// error without consulting the resolver. Test/seeding helper only.
    pub fn seed_failure(&self, host: &str, port: u16, backoff: Duration) {
        self.store_failure(&format!("{host}:{port}"), backoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Shared observability for the mock resolver.
    #[derive(Clone, Default)]
    struct MockState {
        calls: Arc<AtomicUsize>,
        /// Concurrent BLOCKING jobs currently holding a permit, and the peak.
        concurrent: Arc<AtomicUsize>,
        max_concurrent: Arc<AtomicUsize>,
    }

    /// A resolver that models a NON-CANCELLABLE blocking job (like `getaddrinfo`):
    /// it moves the permit into `spawn_blocking` and blocks the OS thread for
    /// `block`, so the permit — and the "job" — outlives an awaiter that times out.
    fn mock_resolver(
        state: MockState,
        answer: Vec<SocketAddr>,
        block: Duration,
        fail: Arc<AtomicBool>,
    ) -> Resolver {
        Arc::new(move |_host, _port, permit| {
            let state = state.clone();
            let answer = answer.clone();
            let fail = fail.clone();
            Box::pin(async move {
                let handle = tokio::task::spawn_blocking(move || {
                    let _permit = permit; // held for the whole blocking job
                    state.calls.fetch_add(1, Ordering::SeqCst);
                    let live = state.concurrent.fetch_add(1, Ordering::SeqCst) + 1;
                    state.max_concurrent.fetch_max(live, Ordering::SeqCst);
                    if !block.is_zero() {
                        std::thread::sleep(block);
                    }
                    state.concurrent.fetch_sub(1, Ordering::SeqCst);
                    if fail.load(Ordering::SeqCst) {
                        Err(std::io::Error::other("mock dns failure"))
                    } else {
                        Ok(answer.clone())
                    }
                });
                match handle.await {
                    Ok(r) => r,
                    Err(e) => Err(std::io::Error::other(format!("join {e}"))),
                }
            })
        })
    }

    fn cache(
        max_conc: usize,
        state: MockState,
        answer: &[&str],
        block: Duration,
        fail: bool,
    ) -> DnsCache {
        let ans: Vec<SocketAddr> = answer.iter().map(|s| addr(s)).collect();
        DnsCache::new(
            max_conc,
            256,
            mock_resolver(state, ans, block, Arc::new(AtomicBool::new(fail))),
        )
    }

    #[tokio::test]
    async fn ip_literal_bypasses_dns_and_cache() {
        let state = MockState::default();
        let c = cache(8, state.clone(), &["9.9.9.9:80"], Duration::ZERO, false);
        let a = c
            .resolve(
                "127.0.0.1",
                8080,
                Duration::from_secs(1),
                Duration::from_secs(30),
                Duration::ZERO,
            )
            .await
            .unwrap();
        assert_eq!(a, vec![addr("127.0.0.1:8080")]);
        let a6 = c
            .resolve(
                "::1",
                443,
                Duration::from_secs(1),
                Duration::from_secs(30),
                Duration::ZERO,
            )
            .await
            .unwrap();
        assert_eq!(a6, vec![addr("[::1]:443")]);
        assert_eq!(
            state.calls.load(Ordering::SeqCst),
            0,
            "IP literals must not resolve"
        );
    }

    #[tokio::test]
    async fn cache_hit_avoids_re_resolution() {
        let state = MockState::default();
        let c = cache(8, state.clone(), &["10.0.0.1:80"], Duration::ZERO, false);
        let (t, ttl) = (Duration::from_secs(1), Duration::from_secs(30));
        for _ in 0..5 {
            let a = c
                .resolve("api.test", 80, t, ttl, Duration::ZERO)
                .await
                .unwrap();
            assert_eq!(a, vec![addr("10.0.0.1:80")]);
        }
        assert_eq!(
            state.calls.load(Ordering::SeqCst),
            1,
            "a fresh answer must not re-resolve"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn singleflight_coalesces_concurrent_successful_lookups() {
        let state = MockState::default();
        let c = cache(
            8,
            state.clone(),
            &["10.0.0.2:80"],
            Duration::from_millis(150),
            false,
        );
        let (t, ttl) = (Duration::from_secs(5), Duration::from_secs(30));
        let mut handles = Vec::new();
        for _ in 0..25 {
            let c = c.clone();
            handles.push(tokio::spawn(async move {
                c.resolve("api.test", 80, t, ttl, Duration::ZERO)
                    .await
                    .unwrap()
            }));
        }
        for h in handles {
            assert_eq!(h.await.unwrap(), vec![addr("10.0.0.2:80")]);
        }
        assert_eq!(
            state.calls.load(Ordering::SeqCst),
            1,
            "25 concurrent successful lookups for one name must coalesce to one resolve"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn singleflight_coalesces_concurrent_failing_lookups() {
        // Finding 1: a FAILING leader must coalesce its waiters too.
        let state = MockState::default();
        let c = cache(8, state.clone(), &[], Duration::from_millis(120), true);
        let (t, ttl) = (Duration::from_secs(5), Duration::from_secs(30));
        let mut handles = Vec::new();
        for _ in 0..5 {
            let c = c.clone();
            handles.push(tokio::spawn(async move {
                c.resolve("bad.test", 80, t, ttl, Duration::ZERO).await
            }));
        }
        for h in handles {
            assert!(
                h.await.unwrap().is_err(),
                "a failing name must error for every caller"
            );
        }
        assert_eq!(
            state.calls.load(Ordering::SeqCst),
            1,
            "5 concurrent FAILING lookups must coalesce to a single resolver call"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn total_timeout_bounds_the_caller_even_while_queued() {
        // A very slow leader; a follower must give up at the TOTAL deadline (its wait
        // on the flight lock is inside the deadline), not wait for the leader.
        let state = MockState::default();
        let c = cache(
            8,
            state,
            &["10.0.0.5:80"],
            Duration::from_millis(800),
            false,
        );
        let ttl = Duration::from_secs(30);
        let leader = {
            let c = c.clone();
            tokio::spawn(async move {
                let _ = c
                    .resolve("slow.test", 80, Duration::from_secs(5), ttl, Duration::ZERO)
                    .await;
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await; // let the leader take the lock
        let start = Instant::now();
        // Follower with a SHORT total timeout must return promptly, not after 800ms.
        let r = c
            .resolve(
                "slow.test",
                80,
                Duration::from_millis(100),
                ttl,
                Duration::ZERO,
            )
            .await;
        let elapsed = start.elapsed();
        assert!(
            r.is_err(),
            "the follower's total deadline elapsed → bounded error"
        );
        assert!(
            elapsed < Duration::from_millis(400),
            "follower exceeded its total deadline ({elapsed:?})"
        );
        let _ = leader.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn underlying_blocking_jobs_are_bounded_after_caller_timeouts() {
        // Finding 2: with max_concurrent=1, even when every caller TIMES OUT, the
        // real (non-cancellable) blocking job count must not exceed the bound.
        let state = MockState::default();
        // Each "getaddrinfo" blocks 400ms holding the permit; callers time out at 60ms.
        let c = cache(
            1,
            state.clone(),
            &["10.0.0.6:80"],
            Duration::from_millis(400),
            false,
        );
        let ttl = Duration::from_secs(30);
        let mut handles = Vec::new();
        for i in 0..6 {
            let c = c.clone();
            handles.push(tokio::spawn(async move {
                let host = format!("h{i}.test"); // distinct names → no coalescing
                let _ = c
                    .resolve(&host, 80, Duration::from_millis(60), ttl, Duration::ZERO)
                    .await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        // Let the blocking job(s) drain so the peak is fully observed.
        tokio::time::sleep(Duration::from_millis(600)).await;
        let peak = state.max_concurrent.load(Ordering::SeqCst);
        assert!(
            peak <= 1,
            "underlying blocking-job concurrency {peak} exceeded the bound 1 after timeouts"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bounded_concurrency_across_distinct_names() {
        let state = MockState::default();
        let limit = 4;
        let c = cache(
            limit,
            state.clone(),
            &["10.0.0.3:80"],
            Duration::from_millis(120),
            false,
        );
        let (t, ttl) = (Duration::from_secs(5), Duration::from_secs(30));
        let mut handles = Vec::new();
        for i in 0..60 {
            let c = c.clone();
            handles.push(tokio::spawn(async move {
                let host = format!("h{i}.test");
                c.resolve(&host, 80, t, ttl, Duration::ZERO).await.unwrap()
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let peak = state.max_concurrent.load(Ordering::SeqCst);
        assert!(
            peak <= limit,
            "resolver concurrency {peak} exceeded the bound {limit}"
        );
        assert_eq!(
            state.calls.load(Ordering::SeqCst),
            60,
            "each distinct name resolves once"
        );
    }

    #[tokio::test]
    async fn serves_stale_last_known_good_during_resolver_failure() {
        let state = MockState::default();
        let fail = Arc::new(AtomicBool::new(false));
        let c = DnsCache::new(
            8,
            64,
            mock_resolver(
                state,
                vec![addr("10.0.0.9:80")],
                Duration::ZERO,
                fail.clone(),
            ),
        );
        let (t, ttl, stale) = (
            Duration::from_secs(1),
            Duration::from_millis(50),
            Duration::from_secs(30),
        );
        let a = c.resolve("api.test", 80, t, ttl, stale).await.unwrap();
        assert_eq!(a, vec![addr("10.0.0.9:80")]);
        fail.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(120)).await;
        let a = c.resolve("api.test", 80, t, ttl, stale).await.unwrap();
        assert_eq!(
            a,
            vec![addr("10.0.0.9:80")],
            "a transient resolver failure must keep serving the last-known-good answer"
        );
    }

    #[tokio::test]
    async fn failure_with_no_prior_answer_is_an_error() {
        let state = MockState::default();
        let c = cache(8, state, &[], Duration::ZERO, true);
        let err = c
            .resolve(
                "never.resolves",
                80,
                Duration::from_secs(1),
                Duration::from_secs(30),
                Duration::from_secs(30),
            )
            .await
            .expect_err("a first-resolve failure with no cached answer must error");
        let _ = err; // caller maps this to a bounded 502
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelled_leader_lets_a_waiter_re_elect_and_succeed() {
        // Finding 1: a leader cancelled mid-resolve (never publishes) must not wedge
        // its waiters — the RAII flight lock releases, one waiter re-elects.
        let state = MockState::default();
        let c = cache(
            8,
            state.clone(),
            &["10.0.0.7:80"],
            Duration::from_millis(200),
            false,
        );
        let ttl = Duration::from_secs(30);
        let leader = {
            let c = c.clone();
            tokio::spawn(async move {
                let _ = c
                    .resolve("re.test", 80, Duration::from_secs(5), ttl, Duration::ZERO)
                    .await;
            })
        };
        tokio::time::sleep(Duration::from_millis(30)).await; // leader holds the flight lock
        leader.abort(); // cancel mid-resolve, before it publishes
        tokio::time::sleep(Duration::from_millis(10)).await;
        // A fresh caller must re-elect itself and succeed.
        let a = c
            .resolve("re.test", 80, Duration::from_secs(5), ttl, Duration::ZERO)
            .await
            .expect("a waiter must re-resolve after the leader is cancelled");
        assert_eq!(a, vec![addr("10.0.0.7:80")]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn leader_panic_is_surfaced_as_a_bounded_error() {
        // Finding 1: a resolver that PANICS must surface as an ordinary error for the
        // caller (Tokio turns a `spawn_blocking` panic into a JoinError), never a hung
        // waiter or a propagated panic.
        let resolver: Resolver = Arc::new(|_h, _p, permit| {
            Box::pin(async move {
                let handle =
                    tokio::task::spawn_blocking(move || -> std::io::Result<Vec<SocketAddr>> {
                        let _permit = permit;
                        panic!("intentional resolver panic");
                    });
                match handle.await {
                    Ok(r) => r,
                    Err(e) => Err(std::io::Error::other(format!("join {e}"))),
                }
            })
        });
        let c = DnsCache::new(8, 64, resolver);
        let r = c
            .resolve(
                "panic.test",
                80,
                Duration::from_secs(2),
                Duration::from_secs(30),
                Duration::ZERO,
            )
            .await;
        assert!(
            r.is_err(),
            "a panicking resolver must yield a bounded error, not a hang/panic"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn repeated_health_cycles_stay_within_the_blocking_bound() {
        // Finding 4: the health prober now resolves through this same cache. Model
        // repeated probe cycles against a slow, non-cancellable resolver with short
        // timeouts (so callers give up while the OS job runs on) and assert the
        // underlying blocking-job peak never exceeds the bound.
        let state = MockState::default();
        let limit = 2;
        let c = cache(
            limit,
            state.clone(),
            &["10.0.0.8:80"],
            Duration::from_millis(300),
            false,
        );
        for _cycle in 0..5 {
            let mut handles = Vec::new();
            for i in 0..8 {
                let c = c.clone();
                handles.push(tokio::spawn(async move {
                    let host = format!("probe{i}.test");
                    let _ = c
                        .resolve(
                            &host,
                            80,
                            Duration::from_millis(40),
                            Duration::from_secs(1),
                            Duration::ZERO,
                        )
                        .await;
                }));
            }
            for h in handles {
                let _ = h.await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Let the last blocking jobs drain and observe the peak.
        tokio::time::sleep(Duration::from_millis(400)).await;
        let peak = state.max_concurrent.load(Ordering::SeqCst);
        assert!(
            peak <= limit,
            "repeated health cycles reached blocking peak {peak}, over the bound {limit}"
        );
    }
}

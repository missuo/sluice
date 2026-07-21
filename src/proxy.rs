//! The config-driven proxy. Every request reads a per-request snapshot of the
//! `Config` (via `ArcSwap`), so a hot reload never changes behaviour mid-request.

use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use ipnet::IpNet;
use maxminddb::geoip2;
use pingora_cache::cache_control::CacheControl;
use pingora_cache::eviction::simple_lru::Manager as LruEviction;
use pingora_cache::filters as cache_filters;
use pingora_cache::lock::CacheLock;
use pingora_cache::{CacheKey, CacheMeta, CacheMetaDefaults, MemCache, NoCacheReason, RespCacheable};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};

use crate::config::{
    Balance, Config, Handler, RateLimit, SubFilter, Upstream, UpstreamGroup, WafField, CF_RANGES,
};
use crate::metrics::*;

fn in_cloudflare(ip: IpAddr) -> bool {
    CF_RANGES.iter().any(|net| net.contains(&ip))
}

// ---- shared helpers ----

fn host_of(session: &Session) -> Option<String> {
    let rh = session.req_header();
    let raw = rh
        .uri
        .host()
        .map(str::to_owned)
        .or_else(|| rh.headers.get("host").and_then(|v| v.to_str().ok()).map(str::to_owned))?;
    Some(raw.split(':').next().unwrap_or(&raw).to_ascii_lowercase())
}

fn header_val<'a>(session: &'a Session, name: &str) -> Option<&'a str> {
    session.req_header().headers.get(name).and_then(|v| v.to_str().ok())
}

fn peer_ip(session: &Session) -> Option<IpAddr> {
    session.client_addr().and_then(|a| a.as_inet()).map(|i| i.ip())
}

/// Trusted client IP. The configured header (e.g. CF-Connecting-IP) is honored
/// ONLY when the TCP peer is a trusted proxy (default: Cloudflare ranges);
/// otherwise the peer IP is used, so a direct client cannot spoof its address.
fn real_client_ip(session: &Session, trusted_header: &str, trusted_proxies: &[IpNet]) -> String {
    let peer = peer_ip(session);
    if is_trusted_peer(peer, trusted_proxies) {
        if let Some(v) = header_val(session, trusted_header).map(str::trim).filter(|s| !s.is_empty()) {
            return v.to_string();
        }
        // Deliberately no X-Forwarded-For fallback: its leftmost entry is
        // client-controlled, so trusting it would let a client behind the proxy
        // spoof its address (and evade the per-IP rate limiter). If the trusted
        // header is absent, fall through to the peer IP.
    }
    peer.map(|p| p.to_string()).unwrap_or_default()
}

fn is_trusted_peer(peer: Option<IpAddr>, trusted_proxies: &[IpNet]) -> bool {
    peer.is_some_and(|p| trusted_proxies.iter().any(|n| n.contains(&p)))
}

fn req_uri(session: &Session) -> String {
    session
        .req_header()
        .uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".to_string())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Normalize a request path the way backends do, so WAF / `deny` / location
/// matching can't be bypassed by encoding: percent-decode, collapse `//` and
/// `.`, resolve `..`, and reject control/NUL bytes or non-UTF-8. Returns None
/// for a malformed path (caller responds 400). Preserves a trailing slash.
fn normalize_path(raw: &str) -> Option<String> {
    let b = raw.as_bytes();
    let mut dec = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let (h, l) = (hex_val(*b.get(i + 1)?)?, hex_val(*b.get(i + 2)?)?);
            dec.push(h * 16 + l);
            i += 3;
        } else {
            dec.push(b[i]);
            i += 1;
        }
    }
    // Reject NUL and control bytes (0x00–0x1F, 0x7F) — never valid in a path and
    // a classic filter-evasion / smuggling vector.
    if dec.iter().any(|&c| c < 0x20 || c == 0x7f) {
        return None;
    }
    let s = std::str::from_utf8(&dec).ok()?;
    let trailing = s.len() > 1 && s.ends_with('/');
    let mut segs: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        match seg {
            "" | "." => {}          // collapse `//` and `.`
            ".." => {
                segs.pop();
            }
            other => segs.push(other),
        }
    }
    let mut out = String::from("/");
    out.push_str(&segs.join("/"));
    if trailing && !out.ends_with('/') {
        out.push('/');
    }
    Some(out)
}

async fn redirect(session: &mut Session, status: u16, location: String, hsts: Option<&str>) -> Result<()> {
    let mut resp = ResponseHeader::build(status, Some(3))?;
    resp.insert_header("Location", location)?;
    resp.insert_header("Content-Length", "0")?;
    if let Some(h) = hsts {
        resp.insert_header("Strict-Transport-Security", h)?;
    }
    session.write_response_header(Box::new(resp), true).await?;
    Ok(())
}

async fn send_status(session: &mut Session, status: u16, hsts: Option<&str>) -> Result<()> {
    let mut resp = ResponseHeader::build(status, Some(2))?;
    resp.insert_header("Content-Length", "0")?;
    if let Some(h) = hsts {
        resp.insert_header("Strict-Transport-Security", h)?;
    }
    session.write_response_header(Box::new(resp), true).await?;
    Ok(())
}

/// Serve a static file from `root`, streamed in chunks off the async runtime so
/// a large file (or slow FS) never blocks the worker or buffers the whole body
/// in memory. Path traversal is rejected two ways: `..` components up front, and
/// a canonicalized-under-root check.
async fn serve_file(
    session: &mut Session,
    root: &str,
    index: &str,
    req_path: &str,
    hsts: Option<&str>,
) -> Result<()> {
    use tokio::io::AsyncReadExt;

    let is_head = session.req_header().method.as_str() == "HEAD";
    let rel = req_path.trim_start_matches('/');
    if rel.split('/').any(|c| c == "..") {
        return send_status(session, 403, hsts).await;
    }
    let mut fpath = std::path::PathBuf::from(root);
    if !rel.is_empty() {
        fpath.push(rel);
    }
    if req_path.ends_with('/') || rel.is_empty() {
        fpath.push(index);
    }

    // Resolve symlinks and confirm the target stays under root (async, non-blocking).
    let (real, base) = match (
        tokio::fs::canonicalize(&fpath).await,
        tokio::fs::canonicalize(root).await,
    ) {
        (Ok(real), Ok(base)) => (real, base),
        _ => return send_status(session, 404, hsts).await,
    };
    if !real.starts_with(&base) {
        return send_status(session, 403, hsts).await; // resolved outside root
    }
    let meta = match tokio::fs::metadata(&real).await {
        Ok(m) if m.is_file() => m,
        _ => return send_status(session, 404, hsts).await, // missing or a directory
    };

    let mut file = match tokio::fs::File::open(&real).await {
        Ok(f) => f,
        Err(_) => return send_status(session, 404, hsts).await,
    };

    let mut resp = ResponseHeader::build(200, Some(4))?;
    resp.insert_header("Content-Type", content_type(&real))?;
    resp.insert_header("Content-Length", meta.len().to_string())?;
    if let Some(h) = hsts {
        resp.insert_header("Strict-Transport-Security", h)?;
    }
    // HEAD: send headers (incl. the GET Content-Length) but no body.
    session.write_response_header(Box::new(resp), is_head).await?;
    if is_head {
        return Ok(());
    }

    // Stream the body in 64 KiB chunks.
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match file.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            // Header (with Content-Length) is already sent; a mid-file read error
            // can only be surfaced by dropping the connection.
            Err(_) => return Err(Error::new_str("static file read error")),
        };
        session
            .write_response_body(Some(bytes::Bytes::copy_from_slice(&buf[..n])), false)
            .await?;
    }
    session.write_response_body(None, true).await?;
    Ok(())
}

fn content_type(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "txt" => "text/plain; charset=utf-8",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// Populate ctx geo fields (country from header; asn/city from MaxMind).
fn geo_lookup(cfg: &Config, ctx: &mut Ctx, session: &Session) {
    let Some(g) = &cfg.geoip else { return };
    if let Some(h) = &g.country_header {
        // Only honor the country header from a trusted proxy (same anti-spoofing
        // as the client-IP header) — otherwise a direct client could forge geo
        // data in the access log and the country metric. And only accept a
        // 2-letter code, so the metric label can't be inflated.
        if is_trusted_peer(peer_ip(session), &cfg.trusted_proxies) {
            let c = header_val(session, h).unwrap_or("").to_ascii_uppercase();
            if c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()) {
                ctx.country = c;
            }
        }
    }
    let Ok(ip) = ctx.client_ip.parse::<IpAddr>() else { return };
    if let Some(r) = &g.asn_reader {
        if let Ok(res) = r.lookup(ip) {
            if let Ok(Some(asn)) = res.decode::<geoip2::Asn>() {
                if let Some(n) = asn.autonomous_system_number {
                    ctx.asn = format!("AS{n}");
                }
                if let Some(o) = asn.autonomous_system_organization {
                    ctx.asn_org = o.replace(' ', "_");
                }
            }
        }
    }
    if let Some(r) = &g.city_reader {
        if let Ok(res) = r.lookup(ip) {
            if let Ok(Some(city)) = res.decode::<geoip2::City>() {
                if let Some(name) = city.city.names.english {
                    ctx.city = name.replace(' ', "_");
                }
                if ctx.country.is_empty() {
                    if let Some(iso) = city.country.iso_code {
                        ctx.country = iso.to_ascii_uppercase();
                    }
                }
            }
        }
    }
}

// ---- rate limiter (state lives in the proxy, survives config reload) ----

struct Bucket {
    tokens: f64,
    last: Instant,
}

// ---- main proxy (TLS listeners) ----

// ---- shared response cache (in-memory, LRU, with thundering-herd lock) ----
static CACHE_STORAGE: LazyLock<MemCache> = LazyLock::new(MemCache::new);
static CACHE_EVICTION: LazyLock<LruEviction> =
    LazyLock::new(|| LruEviction::new(256 * 1024 * 1024)); // 256 MiB
static CACHE_LOCK: LazyLock<CacheLock> = LazyLock::new(|| CacheLock::new(Duration::from_secs(2)));
/// Origin-only freshness: we never invent a TTL here (returns None); the
/// per-location TTL is applied explicitly in `response_cache_filter`, while the
/// origin's own `Cache-Control` is still honored via `resp_cacheable`.
static CACHE_DEFAULTS: CacheMetaDefaults = CacheMetaDefaults::new(|_| None, 0, 0);

/// splitmix64 — a cheap, lock-free PRNG step for `balance "random"`.
fn fast_rand() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    let mut x = SEED.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Whether a Content-Type is text we can safely find/replace in.
fn rewritable_content_type(ct: &str) -> bool {
    let base = ct.split(';').next().unwrap_or("").trim();
    base.starts_with("text/")
        || matches!(
            base,
            "application/json"
                | "application/javascript"
                | "application/xml"
                | "application/xhtml+xml"
                | "image/svg+xml"
                | "application/rss+xml"
        )
}

/// Streaming find/replace over a response body. `data` is the previous carry plus
/// the new chunk; returns (bytes to emit now, carry to prepend to the next
/// chunk). We hold back the last `max_from - 1` bytes (unless `flush`) so a
/// pattern split across two chunks is still matched. Because every scan position
/// `< limit` has at least `max_from` bytes available, a match is always decidable
/// there — carried bytes are never re-scanned/re-replaced.
fn rewrite_stream(
    data: &[u8],
    filters: &[SubFilter],
    max_from: usize,
    flush: bool,
) -> (Vec<u8>, Vec<u8>) {
    let mut out = Vec::with_capacity(data.len());
    let limit = if flush {
        data.len()
    } else {
        data.len().saturating_sub(max_from.saturating_sub(1))
    };
    let mut i = 0;
    while i < limit {
        let mut matched = false;
        for f in filters {
            if data[i..].starts_with(&f.from) {
                out.extend_from_slice(&f.to);
                i += f.from.len();
                matched = true;
                break;
            }
        }
        if !matched {
            out.push(data[i]);
            i += 1;
        }
    }
    (out, data[i..].to_vec())
}

/// Stable string hash (matches the Ketama ring builder in config.rs).
fn str_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// Weighted random selection: pick a point in [0, total_weight) and walk.
fn weighted_random(servers: &[Upstream]) -> usize {
    let total: u64 = servers.iter().map(|s| s.weight as u64).sum();
    if total == 0 {
        return 0;
    }
    let mut r = fast_rand() % total;
    for (i, s) in servers.iter().enumerate() {
        let w = s.weight as u64;
        if r < w {
            return i;
        }
        r -= w;
    }
    servers.len() - 1
}

/// Ketama lookup: hash the key and take the first ring point clockwise.
fn ketama_pick(ring: &[(u64, usize)], client_ip: &str) -> usize {
    if ring.is_empty() {
        return 0;
    }
    let h = str_hash(client_ip);
    let i = ring.partition_point(|(rh, _)| *rh < h);
    ring[i % ring.len()].1
}

/// How long a backend stays marked down after a connect failure.
const HEALTH_COOLDOWN: Duration = Duration::from_secs(10);

/// Active-health state for one backend (populated only when a pool configures a
/// `health-check`). Starts healthy (optimistic, like Caddy) and flips after
/// `unhealthy`/`healthy` consecutive probe results.
struct ActiveHealth {
    healthy: bool,
    ok_streak: u32,
    fail_streak: u32,
    last_probe: Instant,
}

/// Background active health checker: every second it re-reads the live config
/// (so reloads are picked up), probes each backend whose pool set a
/// `health-check` when its interval is due, and flips its health state.
fn spawn_health_prober(cfg: Arc<ArcSwap<Config>>, health: Arc<DashMap<String, ActiveHealth>>) {
    use crate::config::HealthCheck;
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(r) => r,
            Err(e) => {
                log::error!("health: cannot start runtime: {e}");
                return;
            }
        };
        rt.block_on(async move {
            loop {
                // Collect probe targets from the current config: addr → (check, tls, host).
                let snap = cfg.load();
                let mut targets: std::collections::HashMap<String, (HealthCheck, bool, String)> =
                    std::collections::HashMap::new();
                for site in &snap.sites {
                    for loc in &site.locations {
                        if let Handler::Proxy(g) = &loc.handler {
                            if let Some(hc) = &g.health_check {
                                for s in &g.servers {
                                    targets
                                        .entry(format!("{}:{}", s.host, s.port))
                                        .or_insert_with(|| (hc.clone(), s.tls, s.host.clone()));
                                }
                            }
                        }
                    }
                }
                // Forget backends no longer under a health check.
                health.retain(|k, _| targets.contains_key(k));

                let now = Instant::now();
                for (addr, (hc, tls, host)) in &targets {
                    let due = health
                        .get(addr)
                        .map(|h| now.duration_since(h.last_probe) >= hc.interval)
                        .unwrap_or(true);
                    if !due {
                        continue;
                    }
                    let ok = probe(addr, hc, *tls, host).await;
                    let mut e = health.entry(addr.clone()).or_insert(ActiveHealth {
                        healthy: true,
                        ok_streak: 0,
                        fail_streak: 0,
                        last_probe: now,
                    });
                    e.last_probe = now;
                    if ok {
                        e.fail_streak = 0;
                        e.ok_streak = e.ok_streak.saturating_add(1);
                        if !e.healthy && e.ok_streak >= hc.healthy {
                            e.healthy = true;
                            log::info!("health: {addr} is UP");
                        }
                    } else {
                        e.ok_streak = 0;
                        e.fail_streak = e.fail_streak.saturating_add(1);
                        if e.healthy && e.fail_streak >= hc.unhealthy {
                            e.healthy = false;
                            log::warn!("health: {addr} is DOWN");
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    });
}

/// Probe one backend. TCP-connect check by default; an HTTP GET check when a
/// `path` is set on a plaintext backend (TLS backends fall back to connect-level).
async fn probe(addr: &str, hc: &crate::config::HealthCheck, tls: bool, host: &str) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let conn = tokio::time::timeout(hc.timeout, tokio::net::TcpStream::connect(addr)).await;
    let mut stream = match conn {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    let path = match &hc.path {
        Some(p) if !tls => p,
        _ => return true, // TCP-connect (or TLS backend) → connect success is enough
    };
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: sluice-health\r\nConnection: close\r\n\r\n"
    );
    if tokio::time::timeout(hc.timeout, stream.write_all(req.as_bytes())).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 256];
    let n = match tokio::time::timeout(hc.timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return false,
    };
    // Parse the status code from "HTTP/1.x NNN ...".
    let head = String::from_utf8_lossy(&buf[..n]);
    match head.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()) {
        Some(s) => s >= hc.expect_status.0 && s <= hc.expect_status.1,
        None => false,
    }
}

pub struct SluiceProxy {
    cfg: Arc<ArcSwap<Config>>,
    limiter: Arc<DashMap<(String, IpAddr), Bucket>>,
    /// Smooth-weighted-round-robin state (current weights) per (host, location).
    rr: Arc<DashMap<(String, usize), Vec<i64>>>,
    /// Passive health: "host:port" → instant until which it's considered down.
    health: Arc<DashMap<String, Instant>>,
    /// Active health: "host:port" → probe state (only for pools with a health-check).
    health_active: Arc<DashMap<String, ActiveHealth>>,
    /// In-flight request count per backend "host:port", for `balance least-conn`.
    conns: Arc<DashMap<String, i64>>,
}

impl SluiceProxy {
    pub fn new(cfg: Arc<ArcSwap<Config>>) -> Self {
        let limiter: Arc<DashMap<(String, IpAddr), Bucket>> = Arc::new(DashMap::new());
        // Sweep idle buckets so the map can't grow without bound (one entry per
        // distinct client IP otherwise lives forever).
        let sweep = limiter.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(60));
            sweep.retain(|_, b: &mut Bucket| b.last.elapsed() < Duration::from_secs(600));
        });
        // Background active health checker (reads the live config each cycle).
        let health_active: Arc<DashMap<String, ActiveHealth>> = Arc::new(DashMap::new());
        spawn_health_prober(cfg.clone(), health_active.clone());
        SluiceProxy {
            cfg,
            limiter,
            rr: Arc::new(DashMap::new()),
            health: Arc::new(DashMap::new()),
            health_active,
            conns: Arc::new(DashMap::new()),
        }
    }

    /// Move this request's active-connection tally to `addr` (for least-conn):
    /// decrement whatever it was counted against before (e.g. a failover
    /// attempt), increment `addr`, and remember it on the ctx.
    fn count_conn(&self, ctx: &mut Ctx, addr: &str) {
        if ctx.counted_addr.as_deref() == Some(addr) {
            return;
        }
        if let Some(prev) = ctx.counted_addr.take() {
            *self.conns.entry(prev).or_insert(0) -= 1;
        }
        *self.conns.entry(addr.to_string()).or_insert(0) += 1;
        ctx.counted_addr = Some(addr.to_string());
    }

    /// Release this request's active-connection tally at the end (in `logging`).
    fn release_conn(&self, ctx: &mut Ctx) {
        if let Some(addr) = ctx.counted_addr.take() {
            *self.conns.entry(addr).or_insert(0) -= 1;
        }
    }

    /// Is this backend out of rotation — either passively (recent connect failure,
    /// within cooldown) or actively (a configured health check marked it down)?
    fn is_down(&self, addr: &str) -> bool {
        if self.health.get(addr).is_some_and(|until| Instant::now() < *until) {
            return true;
        }
        self.health_active.get(addr).is_some_and(|h| !h.healthy)
    }

    /// Mark a backend down for the cooldown after a connect failure.
    fn mark_down(&self, addr: &str) {
        self.health.insert(addr.to_string(), Instant::now() + HEALTH_COOLDOWN);
    }

    /// Primary pool index for this request per the balance policy (failover then
    /// walks forward from here, skipping down backends).
    fn lb_base(&self, host: &str, loc_idx: usize, group: &UpstreamGroup, client_ip: &str) -> usize {
        let n = group.servers.len();
        if n <= 1 {
            return 0;
        }
        match group.balance {
            Balance::RoundRobin => self.weighted_rr(host, loc_idx, &group.servers),
            Balance::Random => weighted_random(&group.servers),
            Balance::IpHash => (str_hash(client_ip) % n as u64) as usize,
            Balance::Ketama => ketama_pick(&group.ring, client_ip),
            Balance::LeastConn => self.least_conn(&group.servers),
        }
    }

    /// Weighted least-connections: the up backend with the smallest
    /// active-requests / weight ratio. Ties break toward the earlier server.
    fn least_conn(&self, servers: &[Upstream]) -> usize {
        let mut best = 0usize;
        let mut best_score = f64::MAX;
        let mut any_up = false;
        for (i, s) in servers.iter().enumerate() {
            let addr = format!("{}:{}", s.host, s.port);
            if self.is_down(&addr) {
                continue;
            }
            any_up = true;
            let active = self.conns.get(&addr).map(|v| *v).unwrap_or(0).max(0) as f64;
            let score = active / s.weight.max(1) as f64;
            if score < best_score {
                best_score = score;
                best = i;
            }
        }
        // If every backend is down, fall back to server 0; the skip-down walk in
        // upstream_peer will still try to find a live one.
        if any_up {
            best
        } else {
            0
        }
    }

    /// Smooth weighted round-robin (Nginx's algorithm): each pick adds every
    /// backend's weight to its running total, selects the max, then subtracts the
    /// pool's total weight from the winner — even, weight-proportional, and
    /// stateless across reloads (reset when the pool size changes).
    fn weighted_rr(&self, host: &str, loc_idx: usize, servers: &[Upstream]) -> usize {
        let n = servers.len();
        let mut cw = self
            .rr
            .entry((host.to_string(), loc_idx))
            .or_insert_with(|| vec![0i64; n]);
        if cw.len() != n {
            *cw = vec![0i64; n];
        }
        let mut total = 0i64;
        let mut best = 0usize;
        let mut best_cw = i64::MIN;
        for (i, s) in servers.iter().enumerate() {
            let w = s.weight as i64;
            cw[i] += w;
            total += w;
            if cw[i] > best_cw {
                best_cw = cw[i];
                best = i;
            }
        }
        cw[best] -= total;
        best
    }

    /// Token bucket per (host, client-ip). Returns true if allowed.
    fn allow(&self, host: &str, ip: IpAddr, rl: RateLimit) -> bool {
        let now = Instant::now();
        let mut b = self
            .limiter
            .entry((host.to_string(), ip))
            .or_insert(Bucket { tokens: rl.burst, last: now });
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * rl.rps).min(rl.burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct Ctx {
    cfg: Arc<Config>,
    start: Instant,
    host: String,
    site: Option<usize>,
    /// Index into the site's `locations` chosen for this request.
    location: Option<usize>,
    /// Pool base index (before failover offset) for the chosen location.
    lb_base: usize,
    /// Connect-failure retries so far (failover offset into the pool).
    tries: usize,
    /// The upstream address actually dialed, for the access log.
    up_addr: String,
    /// Host header to send to the chosen upstream (None = preserve client Host).
    up_host_header: Option<String>,
    /// Backend "host:port" this request is currently counted against (least-conn).
    counted_addr: Option<String>,
    client_ip: String,
    country: String,
    asn: String,
    asn_org: String,
    city: String,
    /// Per-location body cap enforced while streaming (see `request_body_filter`).
    body_limit: Option<u64>,
    body_seen: u64,
    /// Fallback cache TTL for this request (Some = caching enabled for it).
    cache_ttl: Option<Duration>,
    /// Max cacheable object size for this request's location (bytes).
    cache_max_object: usize,
    /// Whether the response body is being find/replaced (sub-filter).
    rewrite: bool,
    /// Carry-over bytes held between body chunks for the sub-filter matcher.
    rewrite_carry: Vec<u8>,
}

#[async_trait]
impl ProxyHttp for SluiceProxy {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx {
            cfg: self.cfg.load_full(),
            start: Instant::now(),
            host: String::new(),
            site: None,
            location: None,
            lb_base: 0,
            tries: 0,
            up_addr: String::new(),
            up_host_header: None,
            counted_addr: None,
            client_ip: String::new(),
            country: String::new(),
            asn: String::new(),
            asn_org: String::new(),
            city: String::new(),
            body_limit: None,
            body_seen: 0,
            cache_ttl: None,
            cache_max_object: 0,
            rewrite: false,
            rewrite_carry: Vec::new(),
        }
    }

    /// Enable the response cache for this request when its location configures it
    /// and the method is cacheable (GET/HEAD).
    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<()> {
        let cfg = ctx.cfg.clone();
        if let (Some(si), Some(li)) = (ctx.site, ctx.location) {
            if let Some(cc) = &cfg.sites[si].locations[li].cache {
                if cache_filters::request_cacheable(session.req_header()) {
                    ctx.cache_ttl = Some(cc.ttl);
                    ctx.cache_max_object = cc.max_object;
                    session.cache.enable(
                        &*CACHE_STORAGE,
                        Some(&*CACHE_EVICTION),
                        None,
                        Some(&*CACHE_LOCK),
                        None,
                    );
                }
            }
        }
        Ok(())
    }

    /// Cache key: host + method + a coarse Accept-Encoding bucket + full URI.
    /// The encoding bucket keeps a gzip/br body from being served to a client
    /// that only accepts identity (we don't implement full `Vary` yet).
    fn cache_key_callback(&self, session: &Session, ctx: &mut Ctx) -> Result<CacheKey> {
        let req = session.req_header();
        let uri = req.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let ae = req
            .headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let enc = if ae.contains("br") {
            "br"
        } else if ae.contains("gzip") {
            "gzip"
        } else {
            "id"
        };
        Ok(CacheKey::new(
            ctx.host.clone(),
            format!("{}:{}:{}", req.method.as_str(), enc, uri),
            "",
        ))
    }

    /// Decide cacheability: honor the origin's `Cache-Control` first, then fall
    /// back to the location's TTL for a plain 200 the origin didn't mark.
    /// Never caches an authenticated or per-user response.
    fn response_cache_filter(
        &self,
        session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<RespCacheable> {
        let uncacheable = || RespCacheable::Uncacheable(NoCacheReason::OriginNotCache);
        let Some(ttl) = ctx.cache_ttl else {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom("cache off")));
        };
        // A response that sets a cookie is per-user — never cache it.
        if resp.headers.contains_key("set-cookie") {
            return Ok(uncacheable());
        }
        // We don't implement full Vary. Only cache when the response varies on
        // nothing beyond Accept-Encoding (which is already in the key); reject
        // `Vary: *`, `Vary: Cookie`, `Vary: Authorization`, etc. — otherwise one
        // client's variant would be served to everyone.
        if let Some(vary) = resp.headers.get("vary") {
            let ok = vary
                .to_str()
                .map(|v| v.split(',').all(|s| s.trim().eq_ignore_ascii_case("accept-encoding")))
                .unwrap_or(false);
            if !ok {
                return Ok(uncacheable());
            }
        }
        // Object-size cap (bytes) from the location.
        if ctx.cache_max_object > 0 {
            if let Some(len) = resp
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
            {
                if len > ctx.cache_max_object {
                    return Ok(RespCacheable::Uncacheable(NoCacheReason::ResponseTooLarge));
                }
            }
        }

        let req = session.req_header();
        let has_auth = req.headers.contains_key("authorization");
        let has_cookie = req.headers.contains_key("cookie");
        let cc = CacheControl::from_resp_headers(resp);
        let public = cc.as_ref().is_some_and(|c| c.public());

        // A request carrying credentials (Authorization or a Cookie) may get a
        // per-user response. Only cache it if the origin *explicitly* marks it
        // shareable (`Cache-Control: public`) — never via our fallback TTL. This
        // is what stops cache-deception (e.g. /account/statement.css) from
        // leaking one user's data to another.
        if (has_auth || has_cookie) && !public {
            return Ok(uncacheable());
        }

        // Honor explicit origin freshness (max-age/Expires); resp_cacheable also
        // applies the stricter RFC 7234 rule when Authorization is present.
        let via_headers =
            cache_filters::resp_cacheable(cc.as_ref(), resp.clone(), has_auth, &CACHE_DEFAULTS);
        if via_headers.is_cacheable() {
            return Ok(via_headers);
        }
        // No explicit origin freshness → apply our TTL, unless the origin forbade
        // caching. (Authenticated/cookie requests already returned above unless
        // the origin said `public`.)
        if let Some(cc) = &cc {
            if cc.no_store() || cc.no_cache() || cc.private() {
                return Ok(uncacheable());
            }
        }
        if resp.status.as_u16() == 200 {
            let now = SystemTime::now();
            Ok(RespCacheable::Cacheable(CacheMeta::new(now + ttl, now, 0, 0, resp.clone())))
        } else {
            Ok(uncacheable())
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        INFLIGHT.inc();
        let cfg = ctx.cfg.clone();
        ctx.client_ip = real_client_ip(session, &cfg.client_ip_header, &cfg.trusted_proxies);

        let Some(raw_host) = host_of(session) else {
            send_status(session, 400, None).await?;
            return Ok(true);
        };
        let host = cfg.canonical(&raw_host);
        ctx.host = host.clone();
        geo_lookup(&cfg, ctx, session);

        let Some(&idx) = cfg.index.get(&host) else {
            send_status(session, cfg.unknown_host, None).await?;
            return Ok(true);
        };
        ctx.site = Some(idx);
        let site = &cfg.sites[idx];
        let hsts = site.hsts.as_deref(); // added to every short-circuit response too

        // access: cloudflare-only (peer must be a CF edge IP)
        if site.cloudflare_only {
            let ok = peer_ip(session).map(in_cloudflare).unwrap_or(false);
            if !ok {
                send_status(session, 403, hsts).await?;
                return Ok(true);
            }
        }

        // rate limit (per host + client IP)
        if let Some(rl) = site.rate_limit {
            if let Ok(ip) = ctx.client_ip.parse::<IpAddr>() {
                if !self.allow(&host, ip, rl) {
                    send_status(session, 429, hsts).await?;
                    return Ok(true);
                }
            }
        }

        // Normalize the path so matching sees what the backend will (defeats
        // %2e/%2f/`//`/`.`/`..` evasion of WAF, deny, and location routing).
        let raw_path = session.req_header().uri.path();
        let Some(path) = normalize_path(raw_path) else {
            send_status(session, 400, hsts).await?;
            return Ok(true);
        };

        // WAF (site-wide) → block matching requests.
        for rule in &site.waf {
            let blocked = match &rule.field {
                WafField::Path => rule.re.is_match(&path),
                WafField::Query => {
                    rule.re.is_match(session.req_header().uri.query().unwrap_or(""))
                }
                WafField::Method => rule.re.is_match(session.req_header().method.as_str()),
                // Every value (duplicate-header smuggling), lossily decoded so a
                // non-UTF-8 byte can't hide the payload from the regex.
                WafField::Header(name) => session
                    .req_header()
                    .headers
                    .get_all(name.as_str())
                    .iter()
                    .any(|v| rule.re.is_match(&String::from_utf8_lossy(v.as_bytes()))),
            };
            if blocked {
                send_status(session, rule.status, hsts).await?;
                return Ok(true);
            }
        }

        // site-wide deny (nginx `deny`) → 403
        for re in &site.deny {
            if re.is_match(&path) {
                send_status(session, 403, hsts).await?;
                return Ok(true);
            }
        }

        // site-level redirects
        for r in &site.redirects {
            if r.re.is_match(&path) {
                let uri = req_uri(session);
                let loc = r.target.replace("{uri}", &uri).replace("{host}", &host);
                redirect(session, r.status, loc, hsts).await?;
                return Ok(true);
            }
        }

        // route to a location by path (first matching location, declaration order)
        let Some(loc_idx) = site.locations.iter().position(|l| l.matcher.matches(&path)) else {
            send_status(session, 404, hsts).await?;
            return Ok(true);
        };
        ctx.location = Some(loc_idx);
        let loc = &site.locations[loc_idx];

        // per-location deny
        for re in &loc.deny {
            if re.is_match(&path) {
                send_status(session, 403, hsts).await?;
                return Ok(true);
            }
        }

        match &loc.handler {
            // static file server → serve here and short-circuit
            Handler::File { root, index } => {
                serve_file(session, root, index, &path, hsts).await?;
                return Ok(true);
            }
            // proxy → choose the pool member now (round-robin cursor advances once)
            Handler::Proxy(group) => {
                ctx.lb_base = self.lb_base(&host, loc_idx, group, &ctx.client_ip);
            }
        }

        if let Some(max) = loc.max_body {
            // Fast path: reject an over-size declared Content-Length up front.
            let too_big = header_val(session, "content-length")
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|l| l > max);
            if too_big {
                send_status(session, 413, hsts).await?;
                return Ok(true);
            }
            // Slow path: a chunked / no-Content-Length body is still capped while
            // streaming (see `request_body_filter`), so the limit can't be evaded.
            ctx.body_limit = Some(max);
        }

        Ok(false)
    }

    /// Enforce `max-body` on the streamed request body, catching chunked or
    /// HTTP/2 uploads that omit Content-Length (the header check alone misses them).
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
        ctx: &mut Ctx,
    ) -> Result<()> {
        if let (Some(max), Some(chunk)) = (ctx.body_limit, body.as_ref()) {
            ctx.body_seen = ctx.body_seen.saturating_add(chunk.len() as u64);
            if ctx.body_seen > max {
                return Err(Error::new_str("request body exceeds max-body"));
            }
        }
        Ok(())
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let cfg = ctx.cfg.clone();
        let si = ctx.site.ok_or_else(|| Error::new_str("no site matched"))?;
        let li = ctx.location.ok_or_else(|| Error::new_str("no location matched"))?;
        let loc = &cfg.sites[si].locations[li];
        let Handler::Proxy(group) = &loc.handler else {
            return Err(Error::new_str("file-server location reached upstream_peer"));
        };
        // Start at (lb_base picked once in request_filter) + tries (failover
        // offset), then skip past any backend currently marked down. If every
        // member is down, fall back to the start so we still attempt one.
        let n = group.servers.len();
        let start = (ctx.lb_base + ctx.tries) % n;
        let mut chosen = start;
        for k in 0..n {
            let cand = (start + k) % n;
            let s = &group.servers[cand];
            if !self.is_down(&format!("{}:{}", s.host, s.port)) {
                chosen = cand;
                break;
            }
        }
        let up = &group.servers[chosen];
        let addr = format!("{}:{}", up.host, up.port);
        // Account this request against the chosen backend for least-conn (moves
        // the tally if a failover changed the target).
        self.count_conn(ctx, &addr);
        ctx.up_host_header = up.host_header.clone();
        ctx.up_addr = addr;

        // tls + sni for https upstreams (OpenAI/S3); plaintext for bare host:port.
        let mut peer = HttpPeer::new((up.host.as_str(), up.port), up.tls, up.sni.clone());
        peer.options.verify_cert = up.verify;
        peer.options.verify_hostname = up.verify;
        peer.options.connection_timeout = Some(Duration::from_secs(5));
        // Default a read timeout for non-websocket locations (slowloris protection);
        // websockets and explicitly-configured locations keep their own value.
        peer.options.read_timeout = if loc.websocket {
            None
        } else {
            loc.read_timeout.or(Some(Duration::from_secs(60)))
        };
        peer.options.write_timeout = Some(Duration::from_secs(300));
        peer.options.idle_timeout = Some(Duration::from_secs(60));
        Ok(Box::new(peer))
    }

    /// On a connect failure, retry the next server in the pool (failover) until
    /// every member has been tried once.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Ctx,
        mut e: Box<Error>,
    ) -> Box<Error> {
        // The backend we just tried is unreachable — mark it down so subsequent
        // requests skip it during the cooldown.
        if !ctx.up_addr.is_empty() {
            self.mark_down(&ctx.up_addr);
        }
        let cfg = ctx.cfg.clone();
        if let (Some(si), Some(li)) = (ctx.site, ctx.location) {
            if let Handler::Proxy(group) = &cfg.sites[si].locations[li].handler {
                if ctx.tries + 1 < group.servers.len() {
                    ctx.tries += 1;
                    e.set_retry(true);
                }
            }
        }
        e
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        // Strip client-supplied forwarding / URL-override headers so a client
        // can't poison the origin's absolute-URL generation (→ cached XSS via
        // X-Forwarded-Host) or smuggle a different path. We set the trusted ones
        // ourselves below.
        for h in [
            "x-forwarded-host",
            "x-forwarded-server",
            "x-forwarded-scheme",
            "x-forwarded-port",
            "forwarded",
            "x-original-url",
            "x-rewrite-url",
            "x-real-ip",
            "x-forwarded-for",
            "x-forwarded-proto",
        ] {
            upstream_request.remove_header(h);
        }
        upstream_request.insert_header("X-Real-IP", &ctx.client_ip)?;
        upstream_request.insert_header("X-Forwarded-For", &ctx.client_ip)?;
        upstream_request.insert_header("X-Forwarded-Proto", "https")?;
        // Rewrite Host for cross-host (https://) upstreams so OpenAI/S3 see their
        // own hostname; bare host:port upstreams keep the client's Host. Uses the
        // exact server chosen in upstream_peer (health-aware), not a re-derivation.
        if let Some(h) = &ctx.up_host_header {
            upstream_request.insert_header("Host", h.as_str())?;
        }
        // If this location rewrites the response body, ask the origin for an
        // uncompressed response (we can't find/replace inside gzip/br).
        if let (Some(si), Some(li)) = (ctx.site, ctx.location) {
            if !ctx.cfg.sites[si].locations[li].sub_filters.is_empty() {
                upstream_request.remove_header("accept-encoding");
            }
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let cfg = ctx.cfg.clone();
        if let Some(idx) = ctx.site {
            if let Some(hsts) = &cfg.sites[idx].hsts {
                upstream_response.insert_header("Strict-Transport-Security", hsts.as_str())?;
            }
        }
        // Enable response-body rewriting only for an uncompressed text response
        // (the origin was asked not to compress above). The body length changes,
        // so drop Content-Length and let it stream chunked.
        if let (Some(si), Some(li)) = (ctx.site, ctx.location) {
            let loc = &cfg.sites[si].locations[li];
            if !loc.sub_filters.is_empty() {
                let uncompressed = upstream_response
                    .headers
                    .get("content-encoding")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.eq_ignore_ascii_case("identity"))
                    .unwrap_or(true);
                let text = upstream_response
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(rewritable_content_type)
                    .unwrap_or(false);
                if uncompressed && text {
                    ctx.rewrite = true;
                    upstream_response.remove_header("Content-Length");
                }
            }
        }
        Ok(())
    }

    /// Streaming response-body find/replace (nginx `sub_filter`), with carry-over
    /// so a pattern split across chunks still matches.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Ctx,
    ) -> Result<Option<Duration>> {
        if !ctx.rewrite {
            return Ok(None);
        }
        let cfg = ctx.cfg.clone();
        let (Some(si), Some(li)) = (ctx.site, ctx.location) else {
            return Ok(None);
        };
        let loc = &cfg.sites[si].locations[li];
        if loc.sub_filters.is_empty() {
            return Ok(None);
        }
        // input = held-over carry + this chunk
        let mut data = std::mem::take(&mut ctx.rewrite_carry);
        if let Some(chunk) = body.take() {
            data.extend_from_slice(&chunk);
        }
        let (emit, carry) = rewrite_stream(&data, &loc.sub_filters, loc.sub_max_from, end_of_stream);
        ctx.rewrite_carry = carry;
        *body = if emit.is_empty() {
            None
        } else {
            Some(bytes::Bytes::from(emit))
        };
        Ok(None)
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Ctx) {
        INFLIGHT.dec();
        self.release_conn(ctx); // release the least-conn tally for this request
        let status = session.response_written().map(|r| r.status.as_u16()).unwrap_or(0);
        // Only a matched site becomes a metric label; an unmatched (attacker-
        // controlled) Host is collapsed to "-" so it can't inflate cardinality.
        let host = if ctx.site.is_some() { ctx.host.as_str() } else { "-" };
        let elapsed = ctx.start.elapsed();

        REQUESTS.with_label_values(&[host, &format!("{}xx", status / 100)]).inc();
        RESPONSES.with_label_values(&[host, &status.to_string()]).inc();
        LATENCY.with_label_values(&[host]).observe(elapsed.as_secs_f64());
        RESP_BYTES.with_label_values(&[host]).inc_by(session.body_bytes_sent() as u64);
        REQ_BYTES.with_label_values(&[host]).inc_by(session.body_bytes_read() as u64);
        if e.is_some() || matches!(status, 502 | 503 | 504) {
            UPSTREAM_ERRORS.with_label_values(&[host]).inc();
        }
        let country_metric = ctx
            .cfg
            .geoip
            .as_ref()
            .is_some_and(|g| g.metric_labels.iter().any(|l| l == "country"));
        if country_metric && !ctx.country.is_empty() {
            REQUESTS_BY_COUNTRY.with_label_values(&[ctx.country.as_str()]).inc();
        }

        // geo fields for the access log, per configured log-fields
        let geo = ctx
            .cfg
            .geoip
            .as_ref()
            .map(|g| {
                let parts: Vec<&str> = g
                    .log_fields
                    .iter()
                    .filter_map(|f| match f.as_str() {
                        "country" => Some(ctx.country.as_str()),
                        "asn" => Some(ctx.asn.as_str()),
                        "asn-org" => Some(ctx.asn_org.as_str()),
                        "city" => Some(ctx.city.as_str()),
                        _ => None,
                    })
                    .filter(|s| !s.is_empty())
                    .collect();
                if parts.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", parts.join(" "))
                }
            })
            .unwrap_or_default();

        let client = if ctx.client_ip.is_empty() { "-" } else { ctx.client_ip.as_str() };
        let method = session.req_header().method.as_str().to_owned();
        let path = session.req_header().uri.path().to_owned();
        let err = e.map(|e| format!(" err={e}")).unwrap_or_default();
        let up = if ctx.up_addr.is_empty() { "-" } else { ctx.up_addr.as_str() };
        // Sub-millisecond precision: static/short-circuit responses are < 1ms,
        // which as_millis() truncates to a misleading "0ms".
        log::info!(
            "{client}{geo} {method} {host}{path} -> {status} {:.3}ms up={up}{err}",
            elapsed.as_secs_f64() * 1000.0,
        );
    }
}

// ---- redirect-only proxy (:80 → https) ----

pub struct RedirectProxy {
    /// Config handle, used to validate the Host before redirecting (so :80 can't
    /// be turned into an open redirect to an arbitrary host).
    pub cfg: Arc<ArcSwap<Config>>,
    /// When ACME is enabled, HTTP-01 challenge tokens are answered here on :80.
    pub challenges: Option<crate::acme::ChallengeStore>,
}

#[async_trait]
impl ProxyHttp for RedirectProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let path = session.req_header().uri.path().to_owned();
        if let Some(ch) = &self.challenges {
            if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
                if let Some(keyauth) = ch.load().get(token).cloned() {
                    let mut resp = ResponseHeader::build(200, Some(2))?;
                    resp.insert_header("Content-Type", "text/plain")?;
                    resp.insert_header("Content-Length", keyauth.len().to_string())?;
                    session.write_response_header(Box::new(resp), false).await?;
                    session
                        .write_response_body(Some(bytes::Bytes::from(keyauth)), true)
                        .await?;
                    return Ok(true);
                }
            }
        }
        // Redirect to https, but only for a Host we actually serve (or a known
        // alias). An unrecognized Host gets 400 rather than a 301 to an arbitrary
        // location, so :80 can't be used as an open redirector.
        let host = host_of(session).unwrap_or_default();
        let cfg = self.cfg.load();
        let known = !host.is_empty()
            && (cfg.index.contains_key(&host) || cfg.index.contains_key(&cfg.canonical(&host)));
        if !known {
            send_status(session, 400, None).await?;
            return Ok(true);
        }
        let uri = req_uri(session);
        redirect(session, 301, format!("https://{host}{uri}"), None).await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Err(Error::new_str("redirect listener never proxies"))
    }
}

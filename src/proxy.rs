//! The config-driven proxy. Every request reads a per-request snapshot of the
//! `Config` (via `ArcSwap`), so a hot reload never changes behaviour mid-request.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use ipnet::IpNet;
use maxminddb::geoip2;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};

use crate::config::{Balance, Config, Handler, RateLimit, UpstreamGroup, WafField, CF_RANGES};
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

/// splitmix64 — a cheap, lock-free PRNG step for `balance "random"`.
fn fast_rand() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    let mut x = SEED.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

pub struct SluiceProxy {
    cfg: Arc<ArcSwap<Config>>,
    limiter: Arc<DashMap<(String, IpAddr), Bucket>>,
    /// Round-robin cursor per (host, location index).
    rr: Arc<DashMap<(String, usize), u64>>,
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
        SluiceProxy { cfg, limiter, rr: Arc::new(DashMap::new()) }
    }

    /// Base index into the pool for this request (before failover offset).
    fn lb_base(&self, host: &str, loc_idx: usize, group: &UpstreamGroup, client_ip: &str) -> usize {
        let n = group.servers.len();
        if n <= 1 {
            return 0;
        }
        match group.balance {
            Balance::RoundRobin => {
                let mut c = self.rr.entry((host.to_string(), loc_idx)).or_insert(0);
                let v = *c;
                *c = c.wrapping_add(1);
                (v % n as u64) as usize
            }
            Balance::Random => (fast_rand() % n as u64) as usize,
            Balance::IpHash => {
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                client_ip.hash(&mut h);
                (h.finish() % n as u64) as usize
            }
        }
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
    client_ip: String,
    country: String,
    asn: String,
    asn_org: String,
    city: String,
    /// Per-location body cap enforced while streaming (see `request_body_filter`).
    body_limit: Option<u64>,
    body_seen: u64,
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
            client_ip: String::new(),
            country: String::new(),
            asn: String::new(),
            asn_org: String::new(),
            city: String::new(),
            body_limit: None,
            body_seen: 0,
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

        let path = session.req_header().uri.path().to_owned();

        // WAF (site-wide) → block matching requests.
        for rule in &site.waf {
            let hay = match &rule.field {
                WafField::Path => path.as_str(),
                WafField::Query => session.req_header().uri.query().unwrap_or(""),
                WafField::Method => session.req_header().method.as_str(),
                WafField::Header(name) => header_val(session, name).unwrap_or(""),
            };
            if rule.re.is_match(hay) {
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
        // (lb_base picked once in request_filter) + tries (advanced on failover).
        let up = &group.servers[(ctx.lb_base + ctx.tries) % group.servers.len()];
        ctx.up_addr = format!("{}:{}", up.host, up.port);

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
        upstream_request.insert_header("X-Real-IP", &ctx.client_ip)?;
        upstream_request.insert_header("X-Forwarded-For", &ctx.client_ip)?;
        upstream_request.insert_header("X-Forwarded-Proto", "https")?;
        // Rewrite Host for cross-host (https://) upstreams so OpenAI/S3 see their
        // own hostname; bare host:port upstreams keep the client's Host.
        let cfg = ctx.cfg.clone();
        if let (Some(si), Some(li)) = (ctx.site, ctx.location) {
            if let Handler::Proxy(group) = &cfg.sites[si].locations[li].handler {
                let up = &group.servers[(ctx.lb_base + ctx.tries) % group.servers.len()];
                if let Some(h) = &up.host_header {
                    upstream_request.insert_header("Host", h.as_str())?;
                }
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
        if let Some(idx) = ctx.site {
            if let Some(hsts) = &ctx.cfg.sites[idx].hsts {
                upstream_response.insert_header("Strict-Transport-Security", hsts.as_str())?;
            }
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Ctx) {
        INFLIGHT.dec();
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

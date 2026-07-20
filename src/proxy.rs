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

use crate::config::{Config, RateLimit, CF_RANGES};
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
    let peer_trusted = peer.is_some_and(|p| trusted_proxies.iter().any(|n| n.contains(&p)));
    if peer_trusted {
        if let Some(v) = header_val(session, trusted_header).map(str::trim).filter(|s| !s.is_empty()) {
            return v.to_string();
        }
        if let Some(v) = header_val(session, "x-forwarded-for")
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return v.to_string();
        }
    }
    peer.map(|p| p.to_string()).unwrap_or_default()
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

/// Serve a static file from `root`. Blocks on file I/O (fine for small assets;
/// stream large files later). Path traversal is rejected two ways: `..`
/// components up front, and a canonicalized-under-root check.
async fn serve_file(
    session: &mut Session,
    root: &str,
    index: &str,
    req_path: &str,
    hsts: Option<&str>,
) -> Result<()> {
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
    match (fpath.canonicalize(), std::path::Path::new(root).canonicalize()) {
        (Ok(real), Ok(base)) if real.starts_with(&base) => match std::fs::read(&real) {
            Ok(body) => {
                let mut resp = ResponseHeader::build(200, Some(4))?;
                resp.insert_header("Content-Type", content_type(&real))?;
                resp.insert_header("Content-Length", body.len().to_string())?;
                if let Some(h) = hsts {
                    resp.insert_header("Strict-Transport-Security", h)?;
                }
                // HEAD: send headers (incl. the GET Content-Length) but no body.
                session.write_response_header(Box::new(resp), is_head).await?;
                if !is_head {
                    session.write_response_body(Some(bytes::Bytes::from(body)), true).await?;
                }
                Ok(())
            }
            Err(_) => send_status(session, 404, hsts).await,
        },
        (Ok(_), Ok(_)) => send_status(session, 403, hsts).await, // resolved outside root
        _ => send_status(session, 404, hsts).await,
    }
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
        // Only accept a 2-letter code — the header is client-supplied, and it
        // becomes a metric label, so reject anything that could inflate cardinality.
        let c = header_val(session, h).unwrap_or("").to_ascii_uppercase();
        if c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()) {
            ctx.country = c;
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

pub struct SluiceProxy {
    cfg: Arc<ArcSwap<Config>>,
    limiter: Arc<DashMap<(String, IpAddr), Bucket>>,
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
        SluiceProxy { cfg, limiter }
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
    upstream: u16,
    client_ip: String,
    country: String,
    asn: String,
    asn_org: String,
    city: String,
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
            upstream: 0,
            client_ip: String::new(),
            country: String::new(),
            asn: String::new(),
            asn_org: String::new(),
            city: String::new(),
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

        // deny paths (nginx `deny`) → 403
        for re in &site.deny {
            if re.is_match(&path) {
                send_status(session, 403, hsts).await?;
                return Ok(true);
            }
        }

        for r in &site.redirects {
            if r.re.is_match(&path) {
                let uri = req_uri(session);
                let loc = r.target.replace("{uri}", &uri).replace("{host}", &host);
                redirect(session, r.status, loc, hsts).await?;
                return Ok(true);
            }
        }

        // static file server (site has no upstream)
        if let Some(root) = &site.file_root {
            serve_file(session, root, &site.index, &path, hsts).await?;
            return Ok(true);
        }

        if let Some(max) = site.max_body {
            let too_big = header_val(session, "content-length")
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|l| l > max);
            if too_big {
                send_status(session, 413, hsts).await?;
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let idx = ctx.site.ok_or_else(|| Error::new_str("no site matched for request"))?;
        let site = &ctx.cfg.sites[idx];
        let up = site
            .upstream
            .as_ref()
            .ok_or_else(|| Error::new_str("file-server site reached upstream_peer"))?;
        ctx.upstream = up.port;

        // tls + sni for https upstreams (OpenAI/S3); plaintext for bare host:port.
        let mut peer = HttpPeer::new((up.host.as_str(), up.port), up.tls, up.sni.clone());
        peer.options.verify_cert = up.verify;
        peer.options.verify_hostname = up.verify;
        peer.options.connection_timeout = Some(Duration::from_secs(5));
        // Default a read timeout for non-websocket sites (slowloris protection);
        // websockets and explicitly-configured sites keep their own value.
        peer.options.read_timeout = if site.websocket {
            None
        } else {
            site.read_timeout.or(Some(Duration::from_secs(60)))
        };
        peer.options.write_timeout = Some(Duration::from_secs(300));
        peer.options.idle_timeout = Some(Duration::from_secs(60));
        Ok(Box::new(peer))
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
        if let Some(idx) = ctx.site {
            if let Some(up) = &ctx.cfg.sites[idx].upstream {
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
        // Sub-millisecond precision: static/short-circuit responses are < 1ms,
        // which as_millis() truncates to a misleading "0ms".
        log::info!(
            "{client}{geo} {method} {host}{path} -> {status} {:.3}ms up=:{}{err}",
            elapsed.as_secs_f64() * 1000.0,
            ctx.upstream
        );
    }
}

// ---- redirect-only proxy (:80 → https) ----

pub struct RedirectProxy {
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
        let host = host_of(session).unwrap_or_default();
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

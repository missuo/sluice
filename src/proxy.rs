//! The config-driven proxy. Every request reads a per-request snapshot of the
//! `Config` (via `ArcSwap`), so a hot reload never changes behaviour mid-request.

use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};

use crate::config::Config;
use crate::metrics::*;

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

fn peer_ip(session: &Session) -> String {
    session
        .client_addr()
        .and_then(|a| a.as_inet())
        .map(|i| i.ip().to_string())
        .unwrap_or_default()
}

/// Trusted client IP: the configured header (e.g. CF-Connecting-IP), else
/// XFF-left, else the TCP peer.
fn real_client_ip(session: &Session, trusted_header: &str) -> String {
    header_val(session, trusted_header)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            header_val(session, "x-forwarded-for")
                .and_then(|v| v.split(',').next())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| peer_ip(session))
        })
}

fn req_uri(session: &Session) -> String {
    session
        .req_header()
        .uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".to_string())
}

async fn redirect(session: &mut Session, status: u16, location: String) -> Result<()> {
    let mut resp = ResponseHeader::build(status, Some(2))?;
    resp.insert_header("Location", location)?;
    resp.insert_header("Content-Length", "0")?;
    session.write_response_header(Box::new(resp), true).await?;
    Ok(())
}

async fn send_status(session: &mut Session, status: u16) -> Result<()> {
    let mut resp = ResponseHeader::build(status, Some(1))?;
    resp.insert_header("Content-Length", "0")?;
    session.write_response_header(Box::new(resp), true).await?;
    Ok(())
}

// ---- main proxy (TLS listeners) ----

pub struct SluiceProxy {
    pub cfg: Arc<ArcSwap<Config>>,
}

pub struct Ctx {
    cfg: Arc<Config>,
    start: Instant,
    host: String,
    site: Option<usize>,
    upstream: u16,
    country: String,
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
            country: String::new(),
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        INFLIGHT.inc();
        let cfg = ctx.cfg.clone();

        let Some(raw_host) = host_of(session) else {
            send_status(session, 400).await?;
            return Ok(true);
        };
        let (host, _is_test) = cfg.canonical(&raw_host);
        ctx.host = host.clone();

        if let Some(g) = &cfg.geoip {
            if let Some(h) = &g.country_header {
                ctx.country = header_val(session, h).unwrap_or("").to_string();
            }
        }

        let Some(&idx) = cfg.index.get(&host) else {
            send_status(session, cfg.unknown_host).await?;
            return Ok(true);
        };
        ctx.site = Some(idx);
        let site = &cfg.sites[idx];

        let path = session.req_header().uri.path().to_owned();
        for r in &site.redirects {
            if r.re.is_match(&path) {
                let uri = req_uri(session);
                let loc = r.target.replace("{uri}", &uri).replace("{host}", &host);
                redirect(session, r.status, loc).await?;
                return Ok(true);
            }
        }

        if let Some(max) = site.max_body {
            let too_big = header_val(session, "content-length")
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|l| l > max);
            if too_big {
                send_status(session, 413).await?;
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let idx = ctx.site.ok_or_else(|| Error::new_str("no site matched for request"))?;
        let site = &ctx.cfg.sites[idx];
        ctx.upstream = site.upstream_port;

        let mut peer = HttpPeer::new(
            (site.upstream_host.as_str(), site.upstream_port),
            false,
            String::new(),
        );
        peer.options.connection_timeout = Some(Duration::from_secs(5));
        peer.options.read_timeout = if site.websocket { None } else { site.read_timeout };
        peer.options.write_timeout = Some(Duration::from_secs(300));
        peer.options.idle_timeout = Some(Duration::from_secs(60));
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let ip = real_client_ip(session, &ctx.cfg.client_ip_header);
        upstream_request.insert_header("X-Real-IP", &ip)?;
        upstream_request.insert_header("X-Forwarded-For", &ip)?;
        upstream_request.insert_header("X-Forwarded-Proto", "https")?;
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
        let host = if ctx.host.is_empty() { "-" } else { ctx.host.as_str() };
        let elapsed = ctx.start.elapsed();

        REQUESTS.with_label_values(&[host, &format!("{}xx", status / 100)]).inc();
        RESPONSES.with_label_values(&[host, &status.to_string()]).inc();
        LATENCY.with_label_values(&[host]).observe(elapsed.as_secs_f64());
        RESP_BYTES.with_label_values(&[host]).inc_by(session.body_bytes_sent() as u64);
        REQ_BYTES.with_label_values(&[host]).inc_by(session.body_bytes_read() as u64);
        if e.is_some() || matches!(status, 502 | 503 | 504) {
            UPSTREAM_ERRORS.with_label_values(&[host]).inc();
        }

        let geoip_on = ctx.cfg.geoip.is_some();
        if geoip_on && !ctx.country.is_empty() {
            REQUESTS_BY_COUNTRY.with_label_values(&[ctx.country.as_str()]).inc();
        }

        let client = real_client_ip(session, &ctx.cfg.client_ip_header);
        let method = session.req_header().method.as_str().to_owned();
        let path = session.req_header().uri.path().to_owned();
        let geo = if geoip_on && !ctx.country.is_empty() {
            format!(" {}", ctx.country)
        } else {
            String::new()
        };
        let err = e.map(|e| format!(" err={e}")).unwrap_or_default();
        log::info!(
            "{client}{geo} {method} {host}{path} -> {status} {}ms up=:{}{err}",
            elapsed.as_millis(),
            ctx.upstream
        );
    }
}

// ---- redirect-only proxy (:80 → https) ----

pub struct RedirectProxy;

#[async_trait]
impl ProxyHttp for RedirectProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let host = host_of(session).unwrap_or_default();
        let uri = req_uri(session);
        redirect(session, 301, format!("https://{host}{uri}")).await?;
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

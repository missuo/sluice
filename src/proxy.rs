//! The config-driven proxy. Every request reads a per-request snapshot of the
//! `Config` (via `ArcSwap`), so a hot reload never changes behaviour mid-request.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use http::uri::Authority;
use ipnet::IpNet;
use maxminddb::geoip2;
use pingora::apps::ServerApp;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::listeners::ConnectionFilter;
use pingora::prelude::*;
use pingora::protocols::Stream;
use pingora::proxy::{ProxyHttp, Session};
use pingora::server::ShutdownWatch;
use pingora_cache::cache_control::CacheControl;
use pingora_cache::eviction::simple_lru::Manager as LruEviction;
use pingora_cache::eviction::EvictionManager;
use pingora_cache::filters as cache_filters;
use pingora_cache::lock::CacheLock;
use pingora_cache::storage::Storage;
use pingora_cache::{
    CacheKey, CacheMeta, CacheMetaDefaults, MemCache, NoCacheReason, RespCacheable,
};

use crate::config::{
    Balance, Config, Handler, RateLimit, SubFilter, Upstream, UpstreamGroup, WafField, CF_RANGES,
};
use crate::metrics::*;

fn in_cloudflare(ip: IpAddr) -> bool {
    CF_RANGES.iter().any(|net| net.contains(&ip))
}

// ---- shared helpers ----

/// Parse and canonicalize ONE authority (`host` or `host:port`). Returns None for
/// anything ambiguous or malformed: userinfo (`user@host`), a non-numeric /
/// out-of-range / empty port (`host:evil`, `host:`, `host:99999`), trailing
/// junk, whitespace, or a path. `http::uri::Authority::from_str` is lenient
/// about ports and userinfo, so we validate by round-tripping against the
/// canonical `host[:port]` form (host lowercased, port as a real u16). A parsed
/// authority whose input doesn't equal its canonical form is rejected rather
/// than silently truncated the way `split(':')` did.
fn parse_authority(raw: &str) -> Option<Authority> {
    let s = raw.trim();
    if s.is_empty() || s.contains('@') {
        return None;
    }
    let auth: Authority = s.parse().ok()?;
    let host = auth.host();
    if host.is_empty() {
        return None;
    }
    let canonical = match auth.port_u16() {
        Some(p) => format!("{}:{}", host.to_ascii_lowercase(), p),
        None => host.to_ascii_lowercase(),
    };
    // Reject any input that isn't already its own canonical form — this catches a
    // non-numeric/empty/over-range port (port_u16 == None but a `:` is present)
    // and any other trailing junk `Authority` tolerated.
    if !s.eq_ignore_ascii_case(&canonical) {
        return None;
    }
    canonical.parse().ok()
}

/// The single authority this request routes on, or None (→ 400) when the request
/// is ambiguous in a way that lets different hops route differently. Rejects:
/// more than one `Host` header line (duplicate-Host smuggling), an absolute-form
/// request target / `:authority` that does not canonically match `Host`
/// (including port), and any syntactically invalid authority. The returned
/// `Authority` is canonical (host lowercased, numeric port), so routing, the
/// upstream `Host`, and the cache namespace all agree on exactly one value.
fn routed_authority(session: &Session) -> Option<Authority> {
    let rh = session.req_header();

    // Every Host header line. Two lines is a request-smuggling vector (a later
    // hop may read the other one) — reject outright.
    let mut host_lines = rh.headers.get_all("host").iter();
    let host_hdr = host_lines.next();
    if host_lines.next().is_some() {
        return None;
    }
    let host_auth = match host_hdr {
        Some(v) => Some(parse_authority(v.to_str().ok()?)?),
        None => None,
    };

    // Absolute-form target (or HTTP/2 `:authority`) carries its own authority.
    let uri_auth = match rh.uri.authority() {
        Some(a) => Some(parse_authority(a.as_str())?),
        None => None,
    };

    match (uri_auth, host_auth) {
        (Some(u), Some(h)) => {
            // Both present: they MUST match, or the proxy and a downstream hop
            // could route on different names.
            if u.as_str().eq_ignore_ascii_case(h.as_str()) {
                Some(u)
            } else {
                None
            }
        }
        (Some(u), None) => Some(u),
        (None, Some(h)) => Some(h),
        (None, None) => None,
    }
}

/// Iterate the comma-separated tokens across every `Connection` header line
/// (trimmed, non-empty). Each token names a header that is hop-by-hop for THIS
/// hop and must not be forwarded (RFC 9110 §7.6.1).
fn connection_tokens(req: &RequestHeader) -> impl Iterator<Item = &str> {
    req.headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Whether the request is asking to switch protocols (WebSocket / tunnel): an
/// `Upgrade` header, or a `Connection: upgrade` token. Such a request must never
/// touch the response cache — its response is a `101`/upgraded byte stream that
/// can't be stored, and a cached HTTP fallback served to a handshake would hold
/// the upgrade service down for the cache TTL.
fn request_wants_upgrade(req: &RequestHeader) -> bool {
    req.headers.contains_key("upgrade")
        || connection_tokens(req).any(|t| t.eq_ignore_ascii_case("upgrade"))
}

/// Whether `key` is a syntactically valid RFC 6455 `Sec-WebSocket-Key`: the
/// base64 encoding of a 16-byte nonce. 16 bytes encode to exactly 24 base64
/// characters — 22 data characters drawn from the standard alphabet followed by
/// `==` padding. We validate the shape (not the decoded value, which is a random
/// nonce) so an attacker cannot pass an arbitrary short/empty string.
fn is_valid_websocket_key(key: &str) -> bool {
    let b = key.as_bytes();
    // Operate on bytes so a hostile multibyte value can't panic a str slice.
    b.len() == 24
        && &b[22..] == b"=="
        && b[..22]
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
}

/// A SYNTACTICALLY VALID WebSocket upgrade request per RFC 6455 §4.1: an
/// `HTTP/1.1` `GET` carrying `Upgrade: websocket`, a `Connection: upgrade`
/// token, `Sec-WebSocket-Version: 13`, and a valid 16-byte base64
/// `Sec-WebSocket-Key`. Deadlines are relaxed only for such a request on a
/// `websocket` location — never for an ordinary request (or an upgrade-SHAPED
/// request that omits the handshake fields) that merely routes there, which must
/// keep its Slowloris limits. This is defense in depth: the absolute receive
/// deadline is now gated on the ESTABLISHED tunnel (`session.was_upgraded()`),
/// not on this request-side predicate.
fn is_websocket_upgrade_request(req: &RequestHeader) -> bool {
    if req.method != http::Method::GET || req.version != http::Version::HTTP_11 {
        return false;
    }
    let upgrade_ws = req
        .headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if !upgrade_ws || !connection_tokens(req).any(|t| t.eq_ignore_ascii_case("upgrade")) {
        return false;
    }
    let version_13 = req
        .headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "13");
    let valid_key = req
        .headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| is_valid_websocket_key(v.trim()));
    version_13 && valid_key
}

fn header_val<'a>(session: &'a Session, name: &str) -> Option<&'a str> {
    session
        .req_header()
        .headers
        .get(name)
        .and_then(|v| v.to_str().ok())
}

/// Join multiple HTTP/2 `cookie` fields into a single HTTP/1.1 `Cookie` field.
///
/// RFC 9113 §8.2.3 lets an H2 request split its cookies across several `cookie`
/// fields; an H2→non-H2 intermediary MUST rejoin them with `"; "`. We collect
/// every value in wire order, join them byte-exactly, remove ALL original fields,
/// and insert one. Only acts when there are ≥2 fields (a single field — the common
/// case — is left untouched). Values come from already-parsed header values joined
/// with a valid separator, so the reconstructed value is always a valid header.
fn join_split_cookies(req: &mut RequestHeader) -> Result<()> {
    let mut joined: Vec<u8> = Vec::new();
    let mut count = 0usize;
    for v in req.headers.get_all("cookie") {
        if count > 0 {
            joined.extend_from_slice(b"; ");
        }
        joined.extend_from_slice(v.as_bytes());
        count += 1;
    }
    if count > 1 {
        req.remove_header("cookie"); // removes ALL `cookie` lines at once
        let value = http::HeaderValue::from_bytes(&joined)
            .map_err(|_| Error::new_str("invalid joined Cookie value"))?;
        req.insert_header("Cookie", value)?;
    }
    Ok(())
}

/// Result of validating a request's `Content-Length` fields.
#[derive(Debug, PartialEq, Eq)]
enum ContentLength {
    /// No `Content-Length` field (fine — length is 0 or determined by TE).
    Absent,
    /// Exactly one field with a canonical non-negative decimal value.
    One(u64),
    /// Two or more fields, or a single non-canonical value — REJECT as a
    /// smuggling / parser-differential vector.
    Invalid,
}

/// Validate the request's `Content-Length`. HTTP/2 permits multiple compressed
/// `content-length` fields and Sluice downgrades every ordinary request to an
/// HTTP/1.1 origin, so an unchecked duplicate (`Content-Length: 45` then
/// `Content-Length: 4`) is forwarded as two H1 lines — an origin that honors the
/// last value reads a short body and treats the remainder as a pipelined request
/// on the pooled upstream connection (request smuggling / desync). Even EQUAL
/// duplicates are rejected (a parser that sums vs. one that dedups still differ).
/// A single field must be a canonical decimal: ASCII digits only, no sign,
/// whitespace, or leading zero, and within `u64` — anything else is a differential
/// vector too.
fn validate_content_length(req: &RequestHeader) -> ContentLength {
    let mut it = req.headers.get_all("content-length").iter();
    let Some(first) = it.next() else {
        return ContentLength::Absent;
    };
    if it.next().is_some() {
        return ContentLength::Invalid; // 2+ fields — reject even if equal
    }
    let Ok(s) = first.to_str() else {
        return ContentLength::Invalid;
    };
    // Canonical non-negative decimal: 1*DIGIT, no leading zero except "0" itself.
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return ContentLength::Invalid;
    }
    if s.len() > 1 && s.as_bytes()[0] == b'0' {
        return ContentLength::Invalid;
    }
    match s.parse::<u64>() {
        Ok(n) => ContentLength::One(n),
        Err(_) => ContentLength::Invalid, // overflows u64
    }
}

/// Whether the request carries credentials that could make its response per-user
/// (an `Authorization` header or any `Cookie`). Such a request must never share a
/// cache entry with an anonymous one — see `request_cache_filter`.
fn request_has_credentials(req: &RequestHeader) -> bool {
    req.headers.contains_key("authorization") || req.headers.contains_key("cookie")
}

/// Maximum total upstream connect attempts (across a backend's resolved addresses
/// AND configured pool members) for one request. Bounds the failover budget so a
/// hostname resolving to many addresses (e.g. a malicious DNS answer) can't cause
/// an unbounded number of dial attempts.
const MAX_CONNECT_ATTEMPTS: usize = 8;

/// Bound on the number of distinct upstream DNS names cached. A backstop far above
/// the configured upstream set (cache keys are configured host:port, not
/// client-controlled), so it effectively never evicts in practice.
const DNS_CACHE_MAX_ENTRIES: usize = 4096;

/// Outcome of the per-chunk `request_body_filter` decision.
#[derive(Debug, PartialEq, Eq)]
enum BodyDecision {
    /// Keep going; carry the updated cumulative request-body byte count.
    Continue(u64),
    /// The absolute request-assembly deadline elapsed before the body finished.
    DeadlineExceeded,
    /// Cumulative request-body bytes exceeded the `max-body` limit.
    MaxBodyExceeded,
}

/// Pure decision for one `request_body_filter` callback.
///
/// Once the connection has switched protocols (`was_upgraded` — a confirmed
/// `101` WebSocket tunnel), the bytes Pingora routes through this hook are
/// bidirectional TUNNEL frames, NOT an HTTP request body, so BOTH request-body-only
/// controls are bypassed: the `max-body` HTTP *entity* limit must not silently
/// become a tunnel-lifetime byte quota (nginx/Caddy don't do this — it would
/// disconnect a legitimate long-lived socket the moment cumulative client→origin
/// traffic crossed the limit), and the absolute deadline bounds *request assembly*,
/// not tunnel duration. `was_upgraded` only becomes true after the `101`, so every
/// pre-upgrade byte — including a slow-drip upgrade-shaped `POST` or a handshake
/// whose `101` never arrives — is still fully enforced.
///
/// The deadline is checked on EVERY callback including the final one, and `>=`
/// makes the configured boundary itself the cutoff. `body_seen` is left unchanged
/// on the upgraded and deadline paths.
fn request_body_decision(
    was_upgraded: bool,
    elapsed: Duration,
    deadline: Duration,
    body_limit: Option<u64>,
    body_seen: u64,
    chunk_len: u64,
) -> BodyDecision {
    if was_upgraded {
        return BodyDecision::Continue(body_seen);
    }
    if elapsed >= deadline {
        return BodyDecision::DeadlineExceeded;
    }
    match body_limit {
        Some(max) => {
            let seen = body_seen.saturating_add(chunk_len);
            if seen > max {
                BodyDecision::MaxBodyExceeded
            } else {
                BodyDecision::Continue(seen)
            }
        }
        None => BodyDecision::Continue(body_seen),
    }
}

/// Canonicalize an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) back to its
/// `IpAddr::V4` form. A Linux dual-stack `[::]` listener reports IPv4 peers as
/// mapped IPv6, so without this every IPv4 client would be treated as the same
/// exotic IPv6 address (and `/64`-collapse to the single key `::`). Applying it
/// at the peer boundary means connection limiting, rate limiting, trusted-proxy /
/// Cloudflare CIDR checks, geo, and logs all use ONE representation per client.
/// Only the mapped range is rewritten; native IPv6 (incl. `::1`) is untouched.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn peer_ip(session: &Session) -> Option<IpAddr> {
    session
        .client_addr()
        .and_then(|a| a.as_inet())
        .map(|i| canonical_ip(i.ip()))
}

/// Trusted client IP. The configured header (e.g. CF-Connecting-IP) is honored
/// ONLY when the TCP peer is a trusted proxy (default: Cloudflare ranges);
/// otherwise the peer IP is used, so a direct client cannot spoof its address.
fn real_client_ip(session: &Session, trusted_header: &str, trusted_proxies: &[IpNet]) -> String {
    let peer = peer_ip(session);
    if is_trusted_peer(peer, trusted_proxies) {
        // Honor the trusted header only if it parses as an IP — a garbage value
        // (e.g. `X-Forwarded-For: not-an-ip`) must NOT become the client IP, or
        // it would parse-fail downstream and silently skip the per-IP rate limit.
        // Normalize via IpAddr so it's canonical for the limiter/geo keys.
        if let Some(ip) = header_val(session, trusted_header)
            .map(str::trim)
            .and_then(|s| s.parse::<IpAddr>().ok())
        {
            // Canonicalize a mapped `::ffff:a.b.c.d` header value too, so a trusted
            // proxy that forwards the mapped form keys identically to the native V4.
            return canonical_ip(ip).to_string();
        }
        // Absent or malformed header → fall through to the peer IP (no
        // X-Forwarded-For fallback: its leftmost entry is client-controlled).
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

/// Percent-decode a query and turn `+` into space, repeatedly until it stops
/// changing, so any depth of over-encoding (`union%252520select`, …) is caught
/// by a rule written against the literal payload. Returns `(decoded, stabilized)`
/// — `stabilized == false` means it was still decodable at the iteration/length
/// cap (pathologically over-encoded), which the caller treats as an attack
/// (fail closed). Lossy on invalid UTF-8.
fn decode_query(q: &str) -> (String, bool) {
    decode_until_stable(q, true)
}

/// Repeatedly percent-decode `s` until it stops changing, so any depth of
/// over-encoding is caught by a rule written against the literal payload.
/// `plus_is_space` = query semantics (`+`→space); paths pass false. Returns
/// `(decoded, stabilized)`; `stabilized == false` means it was still decoding at
/// the iteration/length cap — the caller treats that as an attack (fail closed).
fn decode_until_stable(s: &str, plus_is_space: bool) -> (String, bool) {
    // A very long input is a DoS risk under repeated decoding — treat as unstable.
    if s.len() > 16 * 1024 {
        return (s.to_owned(), false);
    }
    let mut cur = s.to_owned();
    for _ in 0..16 {
        let next = decode_once(&cur, plus_is_space);
        if next == cur {
            return (cur, true);
        }
        cur = next;
    }
    (cur, false)
}

fn decode_once(s: &str, plus_is_space: bool) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                }
                _ => {
                    out.push(b[i]);
                    i += 1;
                }
            },
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Normalize a request path the way backends do, so WAF / `deny` / location
/// matching can't be bypassed by encoding: percent-decode, collapse `//` and
/// `.`, resolve `..`, and reject control/NUL bytes or non-UTF-8. Returns None
/// for a malformed path (caller responds 400). Preserves a trailing slash.
pub fn normalize_path(raw: &str) -> Option<String> {
    // Percent-decode REPEATEDLY until the bytes stop changing, THEN collapse.
    // Deciding on a single fully-decoded canonical view is what defeats
    // multi-encoding: `%252e%252e` (→ `%2e%2e` → `..`) and `/adm%2569n`
    // (→ `/adm%69n` → `/admin`) collapse to the same string that WAF, `deny`,
    // redirects, and location routing all match on — so a deeper decode by the
    // origin can't reach a path the proxy didn't see. Fail closed (→ 400) if it
    // won't stabilize (pathological over-encoding) or is over-long.
    if raw.len() > 8192 {
        return None;
    }
    let mut cur = raw.as_bytes().to_vec();
    let mut stable = false;
    for _ in 0..16 {
        // Fail CLOSED on any malformed `%` (a `%` not followed by two hex
        // digits) at EVERY round. This catches a raw dangling `%` (`/admin%`,
        // `/admin%zz`) AND the `%25`→literal-`%` case (`/admin%25` decodes to
        // `/admin%`, which a lenient origin might read as `/admin` — the exact
        // WAF bypass). decode_percent_once used to leave a bad `%` as-is and call
        // it "stable", so the path slipped through unnormalized.
        if has_malformed_percent(&cur) {
            return None;
        }
        let next = decode_percent_once(&cur);
        if next == cur {
            stable = true;
            break;
        }
        cur = next;
    }
    if !stable {
        return None;
    }
    // Reject NUL and control bytes (0x00–0x1F, 0x7F) — never valid in a path and
    // a classic filter-evasion / smuggling vector.
    if cur.iter().any(|&c| c < 0x20 || c == 0x7f) {
        return None;
    }
    // Reject backslashes (raw or decoded from `%5c`). Windows/IIS-style origins
    // treat `\` as a path separator, so a `\` that survives our `/`-only
    // normalization becomes a separator/traversal the proxy never saw — a
    // routing/traversal disagreement. Fail closed rather than guess the origin's
    // OS. (decode-until-stable above has already turned `%5c`/`%255c` into `\`.)
    if cur.contains(&b'\\') {
        return None;
    }
    let s = std::str::from_utf8(&cur).ok()?;
    let trailing = s.len() > 1 && s.ends_with('/');
    let mut segs: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        // Strip path parameters (matrix params): Java servlet / Spring origins
        // route `/admin;foo=bar` as `/admin` after dropping everything from `;`.
        // Canonicalize the same way so `/admin;anything` can't slip past a
        // protected `location "/admin"` into a public catch-all. `;` before the
        // first segment char yields an empty segment (collapsed below).
        let seg = seg.split(';').next().unwrap_or(seg);
        match seg {
            "" | "." => {} // collapse `//` and `.`
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

/// Percent-encode a fully-decoded canonical path back into a valid origin-form
/// request target, so the upstream decodes it exactly ONCE to the same canonical
/// bytes the proxy routed on. `normalize_path` returns a percent-DECODED string
/// (it may hold a literal `%`, space, or non-ASCII); forwarding those raw would
/// be an invalid target or, worse, let the origin re-read a literal `%xx` as an
/// escape. We keep the unreserved + pchar set and `/` literal (segment structure
/// is already canonical) and encode everything else — crucially `%` itself.
fn encode_path_for_upstream(path: &str) -> String {
    fn safe(b: u8) -> bool {
        b.is_ascii_alphanumeric()
            // unreserved
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            // sub-delims + ':' '@' that are valid inside a path segment
            || matches!(
                b,
                b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b'=' | b':' | b'@'
            )
            // segment separator (structure is already canonical)
            || b == b'/'
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        if safe(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xf) as usize] as char);
        }
    }
    out
}

/// True if `b` contains a `%` that is NOT followed by two hex digits — a
/// malformed percent-escape. Used to fail closed rather than pass it through.
fn has_malformed_percent(b: &[u8]) -> bool {
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() || hex_val(b[i + 1]).is_none() || hex_val(b[i + 2]).is_none() {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

/// One percent-decode pass over raw path bytes (leaves a `%` that isn't a valid
/// `%XX` escape untouched, so decoding terminates).
fn decode_percent_once(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

async fn redirect(
    session: &mut Session,
    status: u16,
    location: String,
    hsts: Option<&str>,
) -> Result<()> {
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

/// Serve a static file from the docroot pinned by `root_fd` (opened once at
/// config load, symlink-free). The file is opened via `openat` FROM that fd —
/// never by re-resolving a path string — so a low-priv user swapping the docroot
/// path afterwards can't re-route reads, and no symlink UNDER the root is
/// followed. Streamed in chunks off the async runtime; the Content-Length comes
/// from `fstat` on the SAME fd streamed, so length and bytes can't disagree.
async fn serve_file(
    session: &mut Session,
    root_fd: std::sync::Arc<crate::dirs::SecureDir>,
    index: &str,
    req_path: &str,
    hsts: Option<&str>,
) -> Result<()> {
    use tokio::io::AsyncReadExt;

    // A file server only answers GET/HEAD; anything else (POST/PUT/…) gets 405.
    let method = session.req_header().method.as_str();
    if method != "GET" && method != "HEAD" {
        let mut resp = ResponseHeader::build(405, Some(2))?;
        resp.insert_header("Allow", "GET, HEAD")?;
        resp.insert_header("Content-Length", "0")?;
        if let Some(h) = hsts {
            resp.insert_header("Strict-Transport-Security", h)?;
        }
        session.write_response_header(Box::new(resp), true).await?;
        return Ok(());
    }
    let is_head = method == "HEAD";
    let rel = req_path.trim_start_matches('/');

    // Build the path segments to walk under the root. Reject `.`/`..`/empty so
    // traversal can't escape even before the race-free open below.
    let mut comps: Vec<String> = Vec::new();
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return send_status(session, 403, hsts).await;
        }
        comps.push(seg.to_string());
    }
    if req_path.ends_with('/') || comps.is_empty() {
        comps.push(index.to_string());
    }
    let ctype = content_type(std::path::Path::new(
        comps.last().map(String::as_str).unwrap_or(""),
    ));

    // Open the file via `openat` FROM the pinned docroot fd, descending one
    // component at a time with `O_NOFOLLOW` — no path re-resolution, so the
    // docroot can't be re-routed and no symlink under it is followed. Blocking
    // openat syscalls run on the blocking pool.
    let open_res = tokio::task::spawn_blocking(move || root_fd.open_file_under(&comps)).await;
    let file = match open_res {
        Ok(Ok(f)) => tokio::fs::File::from_std(f),
        // ELOOP (a symlink under root), ENOENT, ENOTDIR, or "not a regular file".
        _ => return send_status(session, 404, hsts).await,
    };
    let len = match file.metadata().await {
        Ok(m) => m.len(),
        Err(_) => return send_status(session, 404, hsts).await,
    };
    let mut file = file;

    let mut resp = ResponseHeader::build(200, Some(4))?;
    resp.insert_header("Content-Type", ctype)?;
    resp.insert_header("Content-Length", len.to_string())?;
    if let Some(h) = hsts {
        resp.insert_header("Strict-Transport-Security", h)?;
    }
    // HEAD: send headers (incl. the GET Content-Length) but no body.
    session
        .write_response_header(Box::new(resp), is_head)
        .await?;
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
    let Ok(ip) = ctx.client_ip.parse::<IpAddr>() else {
        return;
    };
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

/// Collapse an IPv6 address to its /64 for rate-limit / connection bucketing (a
/// /64 is the standard end-user allocation; finer granularity lets one subscriber
/// mint unbounded buckets by rotating the low bits). IPv4 is used as-is. An
/// IPv4-mapped IPv6 address is first canonicalized to real IPv4 (see
/// [`canonical_ip`]) — otherwise every mapped IPv4 client would /64-collapse to
/// the single key `::` and share one budget.
fn limiter_key_ip(ip: IpAddr) -> IpAddr {
    match canonical_ip(ip) {
        IpAddr::V4(v) => IpAddr::V4(v),
        IpAddr::V6(v) => {
            let s = v.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

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

/// Whether a FINAL response with `status` to a request using `method` is allowed
/// to carry a representation body (RFC 9110 §6.4.1 / §9.3). We must never change
/// the framing of a bodyless response: 1xx informational, `101`/protocol upgrade,
/// `204`, `205` (Reset Content — no content or trailers), `304`, any response to
/// `HEAD`, and a `2xx` to `CONNECT` (a tunnel) have no body, so rewriting them
/// (dropping Content-Length, adding chunked, or touching an upgraded byte stream)
/// is a protocol violation.
fn response_may_have_body(status: u16, method: &http::Method) -> bool {
    if *method == http::Method::HEAD {
        return false;
    }
    if *method == http::Method::CONNECT && (200..=299).contains(&status) {
        return false;
    }
    !matches!(status, 100..=199 | 204 | 205 | 304)
}

/// What to do with `Content-Length` on a BODYLESS response. STATUS prohibitions
/// take precedence over the request method — a HEAD response to a `204`/`1xx`
/// status must still drop the length RFC 9110 §8.6 forbids there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodylessCl {
    /// Content-Length is forbidden (1xx, 204) — remove it.
    Remove,
    /// Content-Length is legal representation metadata (304, or a HEAD response to
    /// a status that would otherwise carry a body) — keep the origin's.
    Keep,
    /// Emit a canonical `Content-Length: 0` (only `205 Reset Content`) — a
    /// bodyless status Pingora does not special-case, so it needs explicit
    /// zero-length framing.
    ZeroLength,
}

/// Whether the response is a protocol upgrade whose "body" is actually an
/// UPGRADED byte stream (WebSocket frames after `101`, or a tunnel after a
/// successful `2xx` CONNECT). Those bytes reach `response_body_filter` via
/// `HttpTask::UpgradedBody` and MUST pass through untouched — never suppressed or
/// rewritten. (`101` is bodyless as an HTTP *message*, but the connection has
/// switched protocols, so it is not "suppress the body".)
fn is_protocol_upgrade(status: u16, method: &http::Method) -> bool {
    status == 101 || (*method == http::Method::CONNECT && (200..=299).contains(&status))
}

fn bodyless_content_length(status: u16, method: &http::Method) -> BodylessCl {
    // A successful CONNECT tunnel MUST NOT carry Content-Length or
    // Transfer-Encoding (RFC 9110 §9.3.6) — remove it, don't synthesize one.
    if *method == http::Method::CONNECT && (200..=299).contains(&status) {
        return BodylessCl::Remove;
    }
    // Status-level prohibitions come first, so they win over the request method.
    if (100..=199).contains(&status) || status == 204 {
        return BodylessCl::Remove; // CL forbidden (RFC 9110 §8.6)
    }
    if status == 205 {
        return BodylessCl::ZeroLength; // Reset Content: no content — canonicalize
    }
    if status == 304 {
        return BodylessCl::Keep; // legal representation metadata
    }
    // Reaching here the response is bodyless only because of the METHOD: a HEAD of
    // a body-carrying status (200/404/3xx…). Content-Length is the length the GET
    // body would have — legal metadata, keep it.
    BodylessCl::Keep
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

/// Stable string hash — re-exported from config so the Ketama ring build and the
/// per-request lookup use the identical (version-stable FNV-1a) hash.
use crate::config::stable_hash as str_hash;

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
pub fn ketama_pick(ring: &[(u64, usize)], client_ip: &str) -> usize {
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
    /// Fingerprint of the probe config (path/intervals/thresholds/Host/TLS) that
    /// produced this state. When a reload changes the probe config for the same
    /// (site, location, addr), stale streaks and a stale DOWN verdict from the
    /// OLD config must not carry over — the state is reset instead.
    fp: u64,
}

/// Hex-encode the EXACT bytes of every `Accept-Encoding` request line (in order,
/// NUL-separated) as a cache-key component. Byte-exact on purpose: any difference
/// — q-values, client preference order, casing, duplicate lines — yields a
/// distinct key, because the origin negotiates the encoding over the whole header
/// and we don't parse it (see `cache_key_callback`).
pub fn accept_encoding_key<'a>(lines: impl Iterator<Item = &'a [u8]>) -> String {
    let mut ae: Vec<u8> = Vec::new();
    for l in lines {
        ae.extend_from_slice(l);
        ae.push(0); // NUL boundary — cannot appear inside a header value
    }
    let mut hex = String::with_capacity(ae.len() * 2);
    for b in &ae {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Key for the active-health map: a probe is identified by (site host, location
/// index, backend addr), so two pools that share a backend addr but differ in
/// Host / path / thresholds keep independent health verdicts. NUL separates the
/// fields (it can't appear in a host or addr), so the key is unambiguous.
fn active_health_key(host: &str, loc_idx: usize, addr: &str) -> String {
    format!("{host}\u{0}{loc_idx}\u{0}{addr}")
}

/// Background active health checker: every second it re-reads the live config
/// (so reloads are picked up), probes each backend whose pool set a
/// `health-check` when its interval is due, and flips its health state.
fn spawn_health_prober(
    cfg: Arc<ArcSwap<Config>>,
    health: Arc<DashMap<String, ActiveHealth>>,
    dns: crate::dns::DnsCache,
) {
    use crate::config::HealthCheck;
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                log::error!("health: cannot start runtime: {e}");
                return;
            }
        };
        rt.block_on(async move {
            loop {
                // Collect probe targets from the current config. The map key is the
                // *probe identity* — (site host, location index, backend addr) — not
                // just the backend addr: two sites/pools that share a backend but set
                // a different Host / path / thresholds must get independent state and
                // their own probe config, instead of colliding on one entry.
                let snap = cfg.load();
                // key: probe identity → (addr "host:port", host, port, hc, tls,
                // probe Host, config fingerprint).
                type ProbeTarget = (String, String, u16, HealthCheck, bool, String, u64);
                let mut targets: std::collections::HashMap<String, ProbeTarget> =
                    std::collections::HashMap::new();
                // DNS parameters for the probe path (reload-aware).
                let dns_timeout = Duration::from_secs(snap.server.upstream_dns_timeout_secs.max(1));
                let dns_ttl = Duration::from_secs(snap.server.upstream_dns_ttl_secs.max(1));
                let dns_stale = Duration::from_secs(snap.server.upstream_dns_stale_secs);
                for site in &snap.sites {
                    for (li, loc) in site.locations.iter().enumerate() {
                        if let Handler::Proxy(g) = &loc.handler {
                            if let Some(hc) = &g.health_check {
                                for s in &g.servers {
                                    let addr = format!("{}:{}", s.host, s.port);
                                    // Probe with the Host the real requests carry:
                                    // upstream-host / the rewritten https host if set,
                                    // otherwise the *site* vhost (what the client
                                    // sends and what we forward) — NOT the raw backend
                                    // IP, or a name-vhost that only answers for its own
                                    // Host looks DOWN while real traffic succeeds.
                                    let probe_host = s
                                        .host_header
                                        .clone()
                                        .or_else(|| {
                                            (!site.host.contains('*')).then(|| site.host.clone())
                                        })
                                        .unwrap_or_else(|| s.host.clone());
                                    // Fingerprint the effective probe config so a
                                    // reload that changes it resets the state.
                                    let fp = str_hash(&format!(
                                        "{:?}|{:?}|{:?}|{}|{}|{:?}|{}|{probe_host}",
                                        hc.path,
                                        hc.interval,
                                        hc.timeout,
                                        hc.healthy,
                                        hc.unhealthy,
                                        hc.expect_status,
                                        s.tls,
                                    ));
                                    targets
                                        .entry(active_health_key(&site.host, li, &addr))
                                        .or_insert_with(|| {
                                            (
                                                addr,
                                                s.host.clone(),
                                                s.port,
                                                hc.clone(),
                                                s.tls,
                                                probe_host,
                                                fp,
                                            )
                                        });
                                }
                            }
                        }
                    }
                }
                // Forget probe identities no longer under a health check.
                health.retain(|k, _| targets.contains_key(k));

                let now = Instant::now();
                // Probe all due backends CONCURRENTLY (a slow/hung backend must
                // not delay the others — one cycle is bounded by one timeout, not
                // by the sum over the pool).
                let mut tasks = Vec::new();
                for (key, (_addr, be_host, be_port, hc, tls, host, fp)) in targets {
                    let due = health
                        .get(&key)
                        .map(|h| h.fp != fp || now.duration_since(h.last_probe) >= hc.interval)
                        .unwrap_or(true);
                    if !due {
                        continue;
                    }
                    let dns = dns.clone();
                    tasks.push(tokio::spawn(async move {
                        // Resolve the backend through the SHARED, bounded DnsCache
                        // (singleflight + backoff + concurrency cap, coalesced with
                        // request-path lookups) — NOT `TcpStream::connect(hostname)`,
                        // which would spawn an uncancellable per-probe `getaddrinfo`.
                        // A resolution failure counts the backend as DOWN this cycle.
                        let ok = match dns
                            .resolve(&be_host, be_port, dns_timeout, dns_ttl, dns_stale)
                            .await
                        {
                            Ok(addrs) => {
                                // Healthy if ANY resolved address answers (mirrors the
                                // request path's address failover).
                                let mut up = false;
                                for a in addrs {
                                    if probe(a, &hc, tls, &host).await {
                                        up = true;
                                        break;
                                    }
                                }
                                up
                            }
                            Err(_) => false,
                        };
                        (key, hc.healthy, hc.unhealthy, ok, fp)
                    }));
                }
                for t in tasks {
                    let Ok((key, healthy_thr, unhealthy_thr, ok, fp)) = t.await else {
                        continue;
                    };
                    let mut e = health.entry(key.clone()).or_insert(ActiveHealth {
                        healthy: true,
                        ok_streak: 0,
                        fail_streak: 0,
                        last_probe: now,
                        fp,
                    });
                    if e.fp != fp {
                        // Probe config changed on reload — drop the old config's
                        // verdict and streaks rather than inheriting them.
                        *e = ActiveHealth {
                            healthy: true,
                            ok_streak: 0,
                            fail_streak: 0,
                            last_probe: now,
                            fp,
                        };
                        log::info!("health: {key} probe config changed; state reset");
                    }
                    e.last_probe = now;
                    if ok {
                        e.fail_streak = 0;
                        e.ok_streak = e.ok_streak.saturating_add(1);
                        if !e.healthy && e.ok_streak >= healthy_thr {
                            e.healthy = true;
                            log::info!("health: {key} is UP");
                        }
                    } else {
                        e.ok_streak = 0;
                        e.fail_streak = e.fail_streak.saturating_add(1);
                        if e.healthy && e.fail_streak >= unhealthy_thr {
                            e.healthy = false;
                            log::warn!("health: {key} is DOWN");
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    });
}

/// Probe one backend at an ALREADY-RESOLVED socket address. TCP-connect check by
/// default; an HTTP GET check when a `path` is set on a plaintext backend (TLS
/// backends fall back to connect-level). Connecting to a `SocketAddr` (not a
/// hostname) means the health prober never triggers the non-cancellable system
/// resolver itself — DNS is resolved beforehand through the shared, bounded
/// `DnsCache` (round-22 finding 4).
async fn probe(addr: SocketAddr, hc: &crate::config::HealthCheck, tls: bool, host: &str) -> bool {
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
    if tokio::time::timeout(hc.timeout, stream.write_all(req.as_bytes()))
        .await
        .is_err()
    {
        return false;
    }
    // Read until the status line is complete (first CRLF), EOF, a 1 KiB cap, or
    // the timeout — a backend that flushes the status line in fragments (e.g.
    // "HTTP/1." then "1 200 OK\r\n") must not be misread as DOWN off a single
    // short read().
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let _ = tokio::time::timeout(hc.timeout, async {
        let mut chunk = [0u8; 256];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(2).any(|w| w == b"\r\n") || buf.len() >= 1024 {
                        break;
                    }
                }
            }
        }
    })
    .await;
    // A COMPLETE, CRLF-terminated status line is required — a backend that sends
    // "HTTP/1.1 200" then hangs (or EOFs) has NOT answered the probe and must
    // count as DOWN; and the first token must actually be an HTTP version, not
    // arbitrary bytes whose second token happens to be a number.
    let Some(line_end) = buf.windows(2).position(|w| w == b"\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&buf[..line_end]);
    let mut toks = head.split_whitespace();
    if !toks.next().is_some_and(|v| v.starts_with("HTTP/")) {
        return false;
    }
    match toks.next().and_then(|s| s.parse::<u16>().ok()) {
        Some(s) => s >= hc.expect_status.0 && s <= hc.expect_status.1,
        None => false,
    }
}

/// Per-IP limit on the total number of **in-flight** connections — counting both
/// connections still in the pre-handshake / pre-header phase and fully
/// established ones — so a single source can neither hold many open connections
/// nor flood pre-handshake sockets (Slowloris / fd-exhaustion).
///
/// Pingora 0.8 gives us two hooks at different stages, and neither alone is
/// enough, so we use both against one shared counter:
///
///  * **Pre-handshake** — [`AcceptFilter`] (a `ConnectionFilter`) runs right
///    after TCP `accept`, BEFORE Pingora's (hardcoded 60s) TLS handshake. It has
///    no close callback, so a connection admitted here is tracked as *pending*
///    with a timestamp and expires after `pending_ttl` (set to the handshake
///    timeout — by then Pingora has either handed it to `process_new` or closed
///    it). This bounds the pre-handshake sockets a stalled-ClientHello attacker
///    can accumulate.
///  * **Post-handshake** — [`ConnCapApp`] wraps the app's `process_new`, which
///    spans a connection's whole life (H1 keepalive loop / H2 connection). It
///    converts one pending slot into an *established* one and holds a
///    [`ConnGuard`] until the connection closes, giving an EXACT concurrency
///    count with a real close signal.
///
/// `pending + established` per source key may never exceed `max`. The key
/// normalizes IPv6 to its `/64` (via [`limiter_key_ip`]) — the same aggregation
/// the request rate limiter uses — so a subscriber can't mint fresh budgets by
/// rotating the interface-identifier bits of its allocation. Established slots
/// are exact (guard drop is immediate on close); pending slots self-heal via the
/// TTL AND a periodic global sweep, so abandoned handshakes never leave a
/// permanent entry (see [`ConnLimiter::spawn_sweeper`]).
#[derive(Debug)]
pub struct ConnLimiter {
    max: u32,
    pending_ttl: Duration,
    /// How often the background sweeper reclaims expired pending slots / empty
    /// entries.
    sweep_interval: Duration,
    /// Hard ceiling on distinct source keys tracked at once — defense in depth
    /// against a distributed / address-rotating flood filling the table faster
    /// than the sweeper reclaims it. A NEW key beyond this is refused admission.
    max_entries: usize,
    state: DashMap<IpAddr, IpConns>,
}

#[derive(Debug, Default)]
struct IpConns {
    /// Fully-established connections (exact; each holds a `ConnGuard`).
    established: u32,
    /// Accept timestamps of connections not yet through `process_new`. Pruned by
    /// `pending_ttl` (they've since handshaked or been closed by Pingora).
    pending: Vec<Instant>,
}

impl IpConns {
    fn prune(&mut self, now: Instant, ttl: Duration) {
        self.pending.retain(|t| now.duration_since(*t) < ttl);
    }
    fn in_flight(&self) -> u32 {
        self.established.saturating_add(self.pending.len() as u32)
    }
    fn is_empty(&self) -> bool {
        self.established == 0 && self.pending.is_empty()
    }
}

impl ConnLimiter {
    pub fn new(max: u32) -> Self {
        // Match Pingora's hardcoded 60s downstream-handshake timeout: a pending
        // socket is gone (handshaked or dropped) by then, so a slightly-generous
        // TTL never under-counts a live pre-handshake connection.
        ConnLimiter {
            max,
            pending_ttl: Duration::from_secs(60),
            sweep_interval: Duration::from_secs(10),
            max_entries: 1_000_000,
            state: DashMap::new(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.max > 0
    }

    /// Background reclamation: every `sweep_interval`, prune every entry's expired
    /// pending timestamps and drop entries that became empty. This is what makes
    /// abandoned handshakes (no close callback) self-heal even when that source IP
    /// never connects again — without it, expired-but-present entries leak for the
    /// life of the process under a distributed scan or IPv6 address rotation.
    pub fn spawn_sweeper(self: &Arc<Self>) {
        if !self.enabled() {
            return;
        }
        let limiter = self.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(limiter.sweep_interval);
            limiter.sweep_expired(Instant::now());
        });
    }

    fn sweep_expired(&self, now: Instant) {
        self.state.retain(|_, e| {
            e.prune(now, self.pending_ttl);
            !e.is_empty()
        });
    }

    /// Pre-handshake admission (called from the `ConnectionFilter`). Reserves a
    /// *pending* slot for the (normalized) source key, or returns false (→ drop
    /// the TCP connection) when it is already at `max` in-flight or the global
    /// table ceiling is reached.
    fn admit_pending(&self, ip: IpAddr) -> bool {
        let ip = limiter_key_ip(ip);
        let now = Instant::now();
        // Global ceiling: if admitting this source would create a NEW entry and
        // the table is already full, sweep once to reclaim expired state, then
        // refuse if still full. Bounds memory under a distributed / rotating flood.
        if !self.state.contains_key(&ip) && self.state.len() >= self.max_entries {
            self.sweep_expired(now);
            if !self.state.contains_key(&ip) && self.state.len() >= self.max_entries {
                log::warn!("sluice: connection-limiter table full ({} keys); refusing new source {ip} pre-handshake", self.max_entries);
                return false;
            }
        }
        let mut e = self.state.entry(ip).or_default();
        e.prune(now, self.pending_ttl);
        if e.in_flight() >= self.max {
            let empty = e.is_empty();
            drop(e);
            if empty {
                self.state.remove_if(&ip, |_, v| v.is_empty());
            }
            return false;
        }
        e.pending.push(now);
        true
    }

    /// Post-handshake promotion (called from `ConnCapApp::process_new`). Converts
    /// one pending slot into an established one and returns a guard that releases
    /// it on drop (connection close). Enforces the cap again for connections that
    /// reached here without a matching live pending slot (e.g. the pending TTL
    /// expired mid-handshake, or `admit_pending` never ran).
    fn promote(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        let ip = limiter_key_ip(ip);
        let now = Instant::now();
        let mut e = self.state.entry(ip).or_default();
        e.prune(now, self.pending_ttl);
        // Retire the pending slot this connection reserved at accept, if present.
        let had_pending = e.pending.pop().is_some();
        // If no pending slot backed this connection, it isn't already counted in
        // in_flight; admit it only if there is still room.
        if !had_pending && e.established >= self.max {
            let empty = e.is_empty();
            drop(e);
            if empty {
                self.state.remove_if(&ip, |_, v| v.is_empty());
            }
            return None;
        }
        e.established += 1;
        Some(ConnGuard {
            limiter: self.clone(),
            // Store the NORMALIZED key so `release` decrements the same bucket.
            ip,
        })
    }

    fn release(&self, ip: IpAddr) {
        // `ip` is already the normalized key stored in the `ConnGuard`.
        let mut empty = false;
        if let Some(mut e) = self.state.get_mut(&ip) {
            e.established = e.established.saturating_sub(1);
            empty = e.is_empty();
        }
        if empty {
            self.state.remove_if(&ip, |_, v| v.is_empty());
        }
    }

    #[cfg(test)]
    fn established(&self, ip: IpAddr) -> u32 {
        self.state
            .get(&limiter_key_ip(ip))
            .map(|e| e.established)
            .unwrap_or(0)
    }

    #[cfg(test)]
    fn in_flight(&self, ip: IpAddr) -> u32 {
        self.state
            .get(&limiter_key_ip(ip))
            .map(|e| e.in_flight())
            .unwrap_or(0)
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.state.len()
    }
}

/// Held for an established connection's lifetime; frees the slot on drop.
pub struct ConnGuard {
    limiter: Arc<ConnLimiter>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

/// Pre-handshake `ConnectionFilter`: rejects a new TCP connection (before the TLS
/// handshake) when its source IP is already at the in-flight cap. This is the
/// only hook Pingora exposes before the handshake, so it is our sole defense
/// against a partial-ClientHello / pre-handshake socket flood; the exact
/// concurrency accounting happens post-handshake in [`ConnCapApp`].
#[derive(Debug)]
pub struct AcceptFilter {
    limiter: Arc<ConnLimiter>,
}

impl AcceptFilter {
    pub fn new(limiter: Arc<ConnLimiter>) -> Self {
        AcceptFilter { limiter }
    }
}

#[async_trait]
impl ConnectionFilter for AcceptFilter {
    async fn should_accept(&self, addr: Option<&SocketAddr>) -> bool {
        // Fail open when we can't attribute the peer — never drop a connection we
        // can't classify.
        let Some(ip) = addr.map(|a| a.ip()) else {
            return true;
        };
        if self.limiter.admit_pending(ip) {
            true
        } else {
            log::debug!("sluice: per-IP connection cap reached for {ip}; dropping pre-handshake");
            false
        }
    }
}

/// A [`ServerApp`] wrapper that promotes a connection to an *established* slot in
/// [`ConnLimiter`] for the whole `process_new` (one call spans a connection's
/// full lifetime, including the H1 keepalive loop and an H2 connection), giving
/// an exact concurrency count with a real close signal (the guard's `Drop`).
pub struct ConnCapApp<A> {
    inner: Arc<A>,
    limiter: Arc<ConnLimiter>,
}

impl<A> ConnCapApp<A> {
    pub fn new(inner: A, limiter: Arc<ConnLimiter>) -> Self {
        ConnCapApp {
            inner: Arc::new(inner),
            limiter,
        }
    }
}

#[async_trait]
impl<A> ServerApp for ConnCapApp<A>
where
    A: ServerApp + Send + Sync + 'static,
{
    async fn process_new(
        self: &Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        // Fast path when the cap is off: no per-connection bookkeeping / getpeername.
        if !self.limiter.enabled() {
            return self.inner.process_new(stream, shutdown).await;
        }
        // Attribute the connection to its peer IP. If we can't (no socket digest),
        // fail open — we never want to drop a connection we can't classify.
        let ip = stream
            .get_socket_digest()
            .and_then(|d| d.peer_addr().and_then(|a| a.as_inet().map(|s| s.ip())));
        let _guard = match ip {
            Some(ip) => match self.limiter.promote(ip) {
                Some(g) => Some(g),
                None => {
                    log::debug!("sluice: per-IP connection cap reached for {ip}; dropping");
                    return None; // over cap → close immediately
                }
            },
            None => None,
        };
        // Guard is held for the whole connection; released on return (Drop).
        self.inner.process_new(stream, shutdown).await
    }

    async fn cleanup(&self) {
        self.inner.cleanup().await;
    }
}

pub struct SluiceProxy {
    cfg: Arc<ArcSwap<Config>>,
    limiter: Arc<DashMap<(String, IpAddr), Bucket>>,
    /// One shared bucket per host, used when `limiter` is at capacity: new
    /// clients are limited COLLECTIVELY (bounded memory — one entry per host —
    /// but still limited, not fail-open).
    overflow: Arc<DashMap<String, Bucket>>,
    /// One-shot flag so a full limiter table warns once, not per request.
    limiter_full_warned: std::sync::atomic::AtomicBool,
    /// Smooth-weighted-round-robin state (current weights) per (host, location).
    rr: Arc<DashMap<(String, usize), Vec<i64>>>,
    /// Passive health: "host:port" → instant until which it's considered down.
    health: Arc<DashMap<String, Instant>>,
    /// Active health: "host:port" → probe state (only for pools with a health-check).
    health_active: Arc<DashMap<String, ActiveHealth>>,
    /// In-flight request count per backend "host:port", for `balance least-conn`.
    conns: Arc<DashMap<String, i64>>,
    /// Response-cache storage backend (in-memory LRU by default, or disk).
    storage: &'static (dyn Storage + Sync),
    /// Eviction manager for the storage (None when the disk reaper bounds size).
    eviction: Option<&'static (dyn EvictionManager + Sync)>,
    /// TTL-aware upstream DNS cache (singleflight, bounded concurrency, serve-stale).
    dns: crate::dns::DnsCache,
}

impl SluiceProxy {
    /// `disk_root` is the already-provisioned, fd-pinned cache directory (or
    /// `None` for the in-memory LRU). It is provisioned by `main` BEFORE the
    /// proxy is built, so a bad `cache-store` dir is a fatal startup error there
    /// — never a silent downgrade to in-memory here.
    pub fn new(cfg: Arc<ArcSwap<Config>>, disk_root: Option<Arc<crate::dirs::SecureDir>>) -> Self {
        let limiter: Arc<DashMap<(String, IpAddr), Bucket>> = Arc::new(DashMap::new());
        // Sweep idle buckets so the map can't grow without bound (one entry per
        // distinct client IP otherwise lives forever).
        let sweep = limiter.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(60));
            sweep.retain(|_, b: &mut Bucket| b.last.elapsed() < Duration::from_secs(600));
        });
        // Upstream DNS cache. The global resolver-concurrency bound is fixed at
        // startup from the initial config (a reload doesn't resize the semaphore);
        // TTL/stale are read per-request so they stay reload-aware. Built BEFORE the
        // health prober so the prober SHARES it (bounded/coalesced probe-path DNS).
        let max_conc = cfg.load().server.upstream_dns_max_concurrent.max(1) as usize;
        let dns = crate::dns::DnsCache::with_system_resolver(max_conc, DNS_CACHE_MAX_ENTRIES);

        // Background active health checker (reads the live config each cycle).
        let health_active: Arc<DashMap<String, ActiveHealth>> = Arc::new(DashMap::new());
        spawn_health_prober(cfg.clone(), health_active.clone(), dns.clone());

        // Disk cache (fd-pinned root provisioned by main) or the in-memory LRU.
        let (storage, eviction): (
            &'static (dyn Storage + Sync),
            Option<&'static (dyn EvictionManager + Sync)>,
        ) = match disk_root {
            Some(root) => {
                let disk: &'static crate::diskcache::DiskCache =
                    Box::leak(Box::new(crate::diskcache::DiskCache::new(root)));
                log::info!("sluice: response cache = disk");
                (disk, None)
            }
            None => (&*CACHE_STORAGE as _, Some(&*CACHE_EVICTION as _)),
        };

        SluiceProxy {
            cfg,
            limiter,
            overflow: Arc::new(DashMap::new()),
            limiter_full_warned: std::sync::atomic::AtomicBool::new(false),
            rr: Arc::new(DashMap::new()),
            health: Arc::new(DashMap::new()),
            health_active,
            conns: Arc::new(DashMap::new()),
            storage,
            eviction,
            dns,
        }
    }

    /// Seed the upstream DNS cache with a fixed, long-lived answer so an integration
    /// test can exercise multi-address failover deterministically. Test/seeding
    /// helper; never called on the request path.
    pub fn seed_dns(&self, host: &str, port: u16, addrs: Vec<std::net::SocketAddr>) {
        self.dns.seed(
            host,
            port,
            addrs,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        );
    }

    /// Seed a long-lived DNS FAILURE for a backend so an integration test can drive
    /// the DNS-failure pool-failover path deterministically. Test/seeding helper.
    pub fn seed_dns_failure(&self, host: &str, port: u16) {
        self.dns.seed_failure(host, port, Duration::from_secs(3600));
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

    /// Is this backend out of rotation for this specific pool — either passively
    /// (a recent connect failure to the addr, within cooldown; a property of the
    /// addr, so keyed by addr) or actively (this pool's configured health check
    /// marked it down; keyed by the pool's probe identity so two vhosts sharing a
    /// backend don't share a DOWN verdict).
    fn is_down(&self, host: &str, loc_idx: usize, addr: &str) -> bool {
        if self
            .health
            .get(addr)
            .is_some_and(|until| Instant::now() < *until)
        {
            return true;
        }
        self.health_active
            .get(&active_health_key(host, loc_idx, addr))
            .is_some_and(|h| !h.healthy)
    }

    /// Mark a backend down for the cooldown after a connect failure.
    fn mark_down(&self, addr: &str) {
        self.health
            .insert(addr.to_string(), Instant::now() + HEALTH_COOLDOWN);
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
            Balance::LeastConn => self.least_conn(host, loc_idx, &group.servers),
        }
    }

    /// Weighted least-connections: the up backend with the smallest
    /// active-requests / weight ratio. Ties break toward the earlier server.
    fn least_conn(&self, host: &str, loc_idx: usize, servers: &[Upstream]) -> usize {
        let mut best = 0usize;
        let mut best_score = f64::MAX;
        let mut any_up = false;
        for (i, s) in servers.iter().enumerate() {
            let addr = format!("{}:{}", s.host, s.port);
            if self.is_down(host, loc_idx, &addr) {
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

    /// Token bucket per (host, client-key). Returns true if allowed.
    ///
    /// IPv6 clients are bucketed by their /64. The per-client table is
    /// hard-capped; when it is full, a NEW client is limited against a single
    /// shared per-HOST overflow bucket instead of getting its own entry. That
    /// bounds memory (one overflow bucket per configured host) under an
    /// address-rotation flood WITHOUT failing open — rotating clients are then
    /// throttled collectively rather than passing freely. A one-shot warning is
    /// logged when overflow first engages.
    fn allow(&self, host: &str, ip: IpAddr, rl: RateLimit) -> bool {
        const LIMITER_MAX_ENTRIES: usize = 262_144;
        let now = Instant::now();
        let key = (host.to_string(), limiter_key_ip(ip));
        if self.limiter.len() >= LIMITER_MAX_ENTRIES && !self.limiter.contains_key(&key) {
            if !self
                .limiter_full_warned
                .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                log::warn!(
                    "rate-limit table full ({LIMITER_MAX_ENTRIES} buckets); new clients are \
                     throttled against a shared per-host bucket until the 10-min sweep frees space"
                );
            }
            let mut b = self.overflow.entry(host.to_string()).or_insert(Bucket {
                tokens: rl.burst,
                last: now,
            });
            return take_token(&mut b, rl, now);
        }
        let mut b = self.limiter.entry(key).or_insert(Bucket {
            tokens: rl.burst,
            last: now,
        });
        take_token(&mut b, rl, now)
    }
}

/// Refill and try to spend one token. Returns true if the request is allowed.
fn take_token(b: &mut Bucket, rl: RateLimit, now: Instant) -> bool {
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

pub struct Ctx {
    cfg: Arc<Config>,
    start: Instant,
    host: String,
    /// The single canonical routed authority (`host` or `host:port`) — sent as
    /// the upstream `Host` for bare (client-Host-preserving) upstreams so the
    /// origin never sees a duplicate/ambiguous Host.
    authority: String,
    /// The canonical, fully-normalized request path (percent-decoded, dot- and
    /// matrix-segments resolved). Forwarded upstream in origin-form so the proxy
    /// and origin share one path view.
    norm_path: String,
    site: Option<usize>,
    /// Index into the site's `locations` chosen for this request.
    location: Option<usize>,
    /// Pool base index (before failover offset) for the chosen location.
    lb_base: usize,
    /// Connect-failure retries so far (failover offset into the configured pool).
    tries: usize,
    /// Which of the CURRENT backend's resolved addresses to dial next. A hostname
    /// backend's addresses are exhausted (incrementing this) before `tries` advances
    /// to the next configured pool member.
    addr_try: usize,
    /// Number of resolved addresses for the current backend (set in `upstream_peer`,
    /// read in `fail_to_connect` to know when to advance to the next backend).
    up_naddr: usize,
    /// Total connect attempts so far this request, bounded by `MAX_CONNECT_ATTEMPTS`.
    attempts: usize,
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
    /// The response cannot carry a body (bodyless status / HEAD) — discard ALL
    /// upstream body bytes so no content follows a bodyless header, keeping the
    /// downstream framing self-consistent (Pingora 0.8 does not treat e.g. `205`
    /// as bodyless on its own).
    suppress_body: bool,
    /// The request is a syntactically valid WebSocket upgrade (an `Upgrade:
    /// websocket` header together with a `Connection: upgrade` token) to a
    /// `websocket` location. Only THEN are the request upload deadlines relaxed;
    /// an ordinary request to a `websocket` location keeps normal Slowloris
    /// limits. Tunnel timeouts are fully relaxed only after a `101` establishes
    /// the tunnel (see `response_filter`).
    upgrade_request: bool,
}

#[async_trait]
impl ProxyHttp for SluiceProxy {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx {
            cfg: self.cfg.load_full(),
            start: Instant::now(),
            host: String::new(),
            authority: String::new(),
            norm_path: String::new(),
            site: None,
            location: None,
            lb_base: 0,
            tries: 0,
            addr_try: 0,
            up_naddr: 0,
            attempts: 0,
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
            suppress_body: false,
            upgrade_request: false,
        }
    }

    /// Enable the response cache for this request when its location configures it
    /// and the method is cacheable (GET/HEAD).
    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<()> {
        let cfg = ctx.cfg.clone();
        if let (Some(si), Some(li)) = (ctx.site, ctx.location) {
            let loc = &cfg.sites[si].locations[li];
            if let Some(cc) = &loc.cache {
                // NEVER enable (or look up) the cache for a request that asks to
                // upgrade: its response is a 101 / upgraded byte stream that must
                // never be stored, and a cached HTTP fallback at the same URI would
                // otherwise be served to a WebSocket handshake instead of reaching
                // the origin for a 101 — holding the upgrade service down for the
                // TTL. Bypass the cache entirely (no lookup, no store).
                if request_wants_upgrade(session.req_header()) {
                    return Ok(());
                }
                // A location that transforms the body (`sub-filter`) is NOT cached:
                // the streaming, length-changing rewrite needs a real end-of-stream
                // to flush its carry-over, which Pingora's cache-fill path does not
                // deliver (its final `Done` task never reaches `response_body_filter`),
                // so a cache miss truncated the last `sub_max_from-1` bytes. Serving
                // only via the (correct) non-cache path avoids that entirely; a
                // config-load warning flags the `cache` + `sub-filter` combination.
                if !loc.sub_filters.is_empty() {
                    return Ok(());
                }
                // A credential-bearing request (Authorization or any Cookie) must
                // NEVER share a cache entry with an anonymous one: the cache key has
                // no credential/public-policy dimension, so enabling lookup here
                // would let a `Bearer`/`session` request be served an anonymous
                // fallback-TTL entry WITHOUT reaching the origin — crossing the
                // auth/session boundary and suppressing origin authorization. The
                // `response_cache_filter` public-only gate runs only AFTER a miss,
                // so it cannot protect the lookup. Bypass the cache entirely (no
                // lookup, no store) for these requests; a public response admitted
                // from an anonymous request is still served to anonymous clients.
                if request_has_credentials(session.req_header()) {
                    return Ok(());
                }
                if cache_filters::request_cacheable(session.req_header()) {
                    ctx.cache_ttl = Some(cc.ttl);
                    ctx.cache_max_object = cc.max_object;
                    session.cache.enable(
                        self.storage,
                        self.eviction,
                        None,
                        Some(&*CACHE_LOCK),
                        None,
                    );
                    // NOTE: we deliberately do NOT call set_max_file_size_bytes —
                    // pingora surfaces its "response too large" as a proxy error
                    // (a 500 to the client), not a graceful uncached passthrough.
                    // max-object is enforced by the Content-Length check in
                    // response_cache_filter, and total on-disk size by the reaper.
                }
            }
        }
        Ok(())
    }

    /// Cache key: host + method + Accept-Encoding + URI.
    ///
    /// The Accept-Encoding component is the **exact raw bytes** of every
    /// `Accept-Encoding` request line, in order, with an unambiguous field
    /// boundary between lines, hex-encoded. We deliberately do NOT parse
    /// q-values, reorder, lowercase, or merge tokens: the origin performs full
    /// RFC 7231 content negotiation over the whole header (weights *and* client
    /// preference order), so `br;q=.1, gzip;q=1` and `br;q=1, gzip;q=.1` can
    /// legitimately yield different representations. Without a complete
    /// negotiation parser, the only safe assumption is that any byte difference
    /// may select a different encoding — so any byte difference gets its own
    /// cache entry. This trades a little hit rate for never handing a client an
    /// encoding it didn't ask for (we don't implement full `Vary`).
    fn cache_key_callback(&self, session: &Session, ctx: &mut Ctx) -> Result<CacheKey> {
        let req = session.req_header();
        let uri = req.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let ae_hex = accept_encoding_key(
            req.headers
                .get_all("accept-encoding")
                .iter()
                .map(|v| v.as_bytes()),
        );
        // Namespace = the FULL canonical authority (host + any explicit port) +
        // the site's config epoch. The port must be in the key: it is preserved in
        // `ctx.authority` and sent upstream verbatim as `Host`, so the origin can
        // return a different representation for `test.local:1111` vs
        // `test.local:2222`. Keying by the portless `ctx.host` let a client seed a
        // port-variant body into the normal authority's cache (port-variant cache
        // poisoning). A reload/restart/upgrade that changes the site's
        // upstreams/roots/sub-filters bumps the epoch → a fresh namespace, so the
        // persistent disk cache can never serve the OLD config's responses.
        let epoch = ctx
            .site
            .map(|i| ctx.cfg.sites[i].cache_epoch)
            .unwrap_or_default();
        Ok(CacheKey::new(
            format!("{}:{epoch:016x}", ctx.authority),
            format!("{}:ae={}:{}", req.method.as_str(), ae_hex, uri),
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
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "cache off",
            )));
        };
        // A protocol-upgrade (`101`) or any informational (`1xx`) response must
        // NEVER be stored: its "body" is an upgraded byte stream / interim header,
        // not a cacheable representation. Pingora hands a `101` to this filter (it
        // treats it as the final header), and an explicit freshness header would
        // otherwise let `resp_cacheable` (below) admit it before the `status==200`
        // fallback — caching it stalls the upgraded stream ("Sent data after end
        // of body"). Reject it here regardless of freshness headers.
        let status = resp.status.as_u16();
        if (100..=199).contains(&status)
            || is_protocol_upgrade(status, &session.req_header().method)
        {
            return Ok(uncacheable());
        }
        // A response that sets a cookie is per-user — never cache it.
        if resp.headers.contains_key("set-cookie") {
            return Ok(uncacheable());
        }
        // We don't implement full Vary. Only cache when the response varies on
        // nothing beyond Accept-Encoding (which is already in the key); reject
        // `Vary: *`, `Vary: Cookie`, etc. Must check EVERY `Vary` line
        // (get_all) — a `Vary: Cookie` on a second line would otherwise be missed
        // and leak one user's response to another (RFC 9110 §5.2: multiple field
        // lines combine).
        for vary in resp.headers.get_all("vary") {
            let ok = vary
                .to_str()
                .map(|v| {
                    v.split(',')
                        .all(|s| s.trim().eq_ignore_ascii_case("accept-encoding"))
                })
                .unwrap_or(false);
            if !ok {
                return Ok(uncacheable());
            }
        }
        // Object-size cap (bytes) from the location. Enforced via Content-Length;
        // when a cap is set and the origin declares NO length, we can't verify the
        // size, so we refuse to cache (a chunked over-limit body would otherwise
        // slip in — pingora's mid-stream cap surfaces as a 500, so we don't use it).
        if ctx.cache_max_object > 0 {
            match resp
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
            {
                Some(len) if len > ctx.cache_max_object => {
                    return Ok(RespCacheable::Uncacheable(NoCacheReason::ResponseTooLarge));
                }
                Some(_) => {}
                None => return Ok(RespCacheable::Uncacheable(NoCacheReason::ResponseTooLarge)),
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
            Ok(RespCacheable::Cacheable(CacheMeta::new(
                now + ttl,
                now,
                0,
                0,
                resp.clone(),
            )))
        } else {
            Ok(uncacheable())
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        INFLIGHT.inc();
        let cfg = ctx.cfg.clone();
        ctx.client_ip = real_client_ip(session, &cfg.client_ip_header, &cfg.trusted_proxies);

        // Exactly one syntactically valid, canonical authority — or 400. This
        // rejects duplicate Host lines, an absolute-form/`:authority` target that
        // disagrees with Host, and non-numeric/over-range ports, so no later hop
        // can route on a different host (authz bypass / cross-vhost cache
        // poisoning).
        let Some(authority) = routed_authority(session) else {
            send_status(session, 400, None).await?;
            return Ok(true);
        };
        let host = authority.host().to_string(); // lowercased, no port
        ctx.host = host.clone();
        ctx.authority = authority.as_str().to_string();
        geo_lookup(&cfg, ctx, session);

        // Reject request smuggling via `Content-Length` BEFORE any cache lookup or
        // upstream selection. On EVERY downstream protocol: 2+ CL fields (H2 lets a
        // client send several; the H2→H1 downgrade forwards them all) or a single
        // non-canonical value is a desync vector against a pooled H1 origin. After
        // this, re-insert the one canonical value as the SOLE field so exactly one
        // normalized `Content-Length` is forwarded.
        match validate_content_length(session.req_header()) {
            ContentLength::Absent => {}
            ContentLength::One(n) => {
                session
                    .req_header_mut()
                    .insert_header("Content-Length", n.to_string())?;
            }
            ContentLength::Invalid => {
                send_status(session, 400, None).await?;
                return Ok(true);
            }
        }

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

        // Canonical path: `normalize_path` now decodes-until-stable THEN
        // collapses, so `path` is the single fully-decoded view that WAF, deny,
        // redirects, and routing ALL match on — a multi-encoded traversal or
        // payload can't reach a form the origin sees but the proxy didn't.
        // (Owned so it can be re-read after a `&mut session` call.)
        let raw_path = session.req_header().uri.path().to_owned();
        let Some(path) = normalize_path(&raw_path) else {
            send_status(session, 400, hsts).await?;
            return Ok(true);
        };
        // Remember the canonical path so `upstream_request_filter` can forward it
        // in origin-form — the proxy and origin then share ONE path view.
        ctx.norm_path = path.clone();

        // WAF (site-wide) → block matching requests. Skip all of it — including
        // the query decode — when the site has no rules (most requests).
        if !site.waf.is_empty() {
            let has_query_rule = site.waf.iter().any(|r| matches!(r.field, WafField::Query));
            // Only pay for the raw-query copy + multi-round decode when a query
            // rule actually exists.
            let (raw_query, decoded_query) = if has_query_rule {
                let raw = session.req_header().uri.query().unwrap_or("").to_owned();
                let (decoded, stable) = decode_query(&raw);
                if !stable {
                    send_status(session, 403, hsts).await?;
                    return Ok(true);
                }
                (raw, decoded)
            } else {
                (String::new(), String::new())
            };
            for rule in &site.waf {
                let blocked = match &rule.field {
                    // The fully-canonical path OR the raw (as-sent) path, so a
                    // rule written against either the literal or the encoded form
                    // matches, and no depth of encoding evades it.
                    WafField::Path => rule.re.is_match(&path) || rule.re.is_match(&raw_path),
                    // Match both the raw query AND its fully-decoded form, so an
                    // attacker can't slip `union%20select` / `union%2520select`
                    // past a rule written against the literal payload.
                    WafField::Query => {
                        rule.re.is_match(&raw_query) || rule.re.is_match(&decoded_query)
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

        // Slowloris hardening for the request BODY and any keepalive follow-up
        // read: tighten the per-read downstream timeout below Pingora's inherited
        // 60s (this ALSO now applies to H2 — a vendored patch makes the H2 body
        // reader honor it, resetting the stream on a silent upload).
        //
        // AND a per-WRITE downstream timeout so a slow-read (H1) or
        // withheld-`WINDOW_UPDATE` (H2) client can't pin a connection/FD/task
        // draining the response with near-zero bandwidth. Applied to EVERY request
        // on BOTH protocols by default (`set_write_timeout` is honored for H1 and,
        // via a vendored patch, H2), independent of the optional adaptive
        // `min_send_rate`. `min_send_rate` is the STRICTER adaptive H1 policy (a
        // no-op on H2) and takes priority over the flat write timeout on H1 when set.
        //
        // These are set for EVERY request, including a valid WebSocket handshake:
        // an ordinary request to a `websocket` location must keep normal limits
        // (a non-upgrade POST could otherwise slow-drip forever). They are relaxed
        // ONLY after a `101` establishes the tunnel — `response_filter` clears them
        // — so a non-101 fallback response also keeps normal limits.
        ctx.upgrade_request = loc.websocket && is_websocket_upgrade_request(session.req_header());
        session.set_read_timeout(Some(Duration::from_secs(
            cfg.server.downstream_read_timeout_secs,
        )));
        if cfg.server.downstream_write_timeout_secs > 0 {
            session.set_write_timeout(Some(Duration::from_secs(
                cfg.server.downstream_write_timeout_secs,
            )));
        }
        if cfg.server.min_send_rate_bytes > 0 {
            session.set_min_send_rate(Some(cfg.server.min_send_rate_bytes));
        }

        // A sub-filter changes the body length, which is incompatible with byte
        // ranges: a range of the ORIGINAL bytes no longer matches after rewriting.
        // Strip `Range`/`If-Range` from the request NOW — before the cache lookup
        // and before we clone the header upstream — so the cache and the origin
        // both return the FULL representation (a 200, never a 206). The matching
        // `Accept-Ranges`/`Content-Range` are dropped from the response.
        if !loc.sub_filters.is_empty() {
            let rh = session.req_header_mut();
            rh.remove_header("range");
            rh.remove_header("if-range");
        }

        // per-location deny
        for re in &loc.deny {
            if re.is_match(&path) {
                send_status(session, 403, hsts).await?;
                return Ok(true);
            }
        }

        match &loc.handler {
            // static file server → serve here and short-circuit
            Handler::File { root_fd, index, .. } => {
                serve_file(session, root_fd.clone(), index, &path, hsts).await?;
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

    /// Enforce the absolute request-assembly deadline and the streamed `max-body`
    /// cap (catching chunked / HTTP-2 uploads that omit Content-Length, which the
    /// header fast path in `request_filter` misses). Both are request-body-only
    /// controls: once the connection has upgraded to a WebSocket tunnel the bytes
    /// here are tunnel frames, not an HTTP entity, so both are bypassed — see
    /// [`request_body_decision`].
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Ctx,
    ) -> Result<()> {
        // Collapse an EMPTY end-of-stream body chunk to `None`. An HTTP/2 request
        // body that ends with an empty DATA frame carrying END_STREAM reaches this
        // hook as `end_of_stream == true` with `Some(Bytes::new())`. Left intact,
        // Pingora's H1 body writer emits the chunked terminator (`0\r\n\r\n`) for
        // the empty buffer AND emits it again in `finish_body()` — a DOUBLE
        // terminator that a strict pooled origin reads as a bogus pipelined request,
        // so its stray response is later mis-assigned to an unrelated request that
        // reuses the pooled upstream connection (cross-request confusion / pool
        // churn; cf. cloudflare/pingora#935). `None` is Pingora's end-of-body
        // signal, so exactly one terminator is written. This must NOT be done for an
        // empty MID-stream callback (`end_of_stream == false`), where `None` would
        // prematurely signal end-of-body. An empty chunk carries 0 bytes, so this
        // leaves the max-body / deadline accounting below unchanged, and it composes
        // with the tunnel bypass (an upgraded client half-close is correctly end-of-
        // body) and the streamed cap.
        if end_of_stream {
            if let Some(chunk) = body.as_ref() {
                if chunk.is_empty() {
                    *body = None;
                }
            }
        }

        let chunk_len = body.as_ref().map_or(0, |c| c.len() as u64);
        let deadline = Duration::from_secs(ctx.cfg.server.request_timeout_secs);
        match request_body_decision(
            session.was_upgraded(),
            ctx.start.elapsed(),
            deadline,
            ctx.body_limit,
            ctx.body_seen,
            chunk_len,
        ) {
            BodyDecision::Continue(seen) => {
                ctx.body_seen = seen;
                Ok(())
            }
            BodyDecision::DeadlineExceeded => {
                Err(Error::new_str("request exceeded absolute receive deadline"))
            }
            BodyDecision::MaxBodyExceeded => Err(Error::new_str("request body exceeds max-body")),
        }
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let cfg = ctx.cfg.clone();
        let si = ctx.site.ok_or_else(|| Error::new_str("no site matched"))?;
        let li = ctx
            .location
            .ok_or_else(|| Error::new_str("no location matched"))?;
        let loc = &cfg.sites[si].locations[li];
        let Handler::Proxy(group) = &loc.handler else {
            return Err(Error::new_str("file-server location reached upstream_peer"));
        };
        let n = group.servers.len();
        let host = &cfg.sites[si].host;
        let s = &cfg.server;
        let dns_timeout = Duration::from_secs(s.upstream_dns_timeout_secs.max(1));
        let dns_ttl = Duration::from_secs(s.upstream_dns_ttl_secs.max(1));
        let dns_stale = Duration::from_secs(s.upstream_dns_stale_secs);

        // Bounded backend selection + RESOLUTION loop. A DNS failure happens here,
        // BEFORE any `HttpPeer` exists, so Pingora never calls `fail_to_connect` for
        // it — if we returned `Err` immediately, one backend's resolver failure would
        // 502 the request even when another pool member is healthy. Instead we fail
        // over across configured members on a DNS failure too: mark ONLY the failing
        // backend down, advance `tries`, reset `addr_try`, consume the shared
        // `MAX_CONNECT_ATTEMPTS` budget, and try the next member. The resolved address
        // set is retained and `ctx.addr_try` selects which to dial so
        // `fail_to_connect` can exhaust one backend's addresses before advancing.
        let (up, resolved) = loop {
            // Start at (lb_base picked once in request_filter) + tries (failover
            // offset), then skip past any backend currently marked down. If every
            // member is down, fall back to the start so we still attempt one.
            let start = (ctx.lb_base + ctx.tries) % n;
            let mut chosen = start;
            for k in 0..n {
                let cand = (start + k) % n;
                let s = &group.servers[cand];
                if !self.is_down(host, li, &format!("{}:{}", s.host, s.port)) {
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

            // Resolve off the request path (TTL cache, singleflight, bounded
            // concurrency, serve-stale). An IP literal skips DNS entirely; a resolver
            // outage/NXDOMAIN/empty answer with no cached answer is an error we fail
            // over on (never a panic — the stock `HttpPeer::new((hostname, ..))` would
            // `unwrap`-panic here, cf. pingora #921).
            match self
                .dns
                .resolve(&up.host, up.port, dns_timeout, dns_ttl, dns_stale)
                .await
            {
                Ok(addrs) => {
                    // `resolve` only returns `Ok` with a non-empty set.
                    ctx.up_naddr = addrs.len();
                    break (up, addrs[ctx.addr_try % addrs.len()]);
                }
                Err(e) => {
                    // This backend can't be resolved. Mark it down and try the next
                    // healthy member, bounded by the shared connect-attempt budget.
                    self.mark_down(&ctx.up_addr);
                    ctx.attempts += 1;
                    if ctx.attempts < MAX_CONNECT_ATTEMPTS && ctx.tries + 1 < n {
                        ctx.tries += 1;
                        ctx.addr_try = 0;
                        continue;
                    }
                    return Err(Error::because(
                        HTTPStatus(502),
                        format!("upstream DNS resolution failed for {:?}", up.host),
                        e,
                    ));
                }
            }
        };

        // Build the peer from the RESOLVED address. `std::net::SocketAddr`'s
        // `ToSocketAddrs` is the trivial identity (no DNS, cannot panic). Crucially,
        // the SNI stays the ORIGINAL DNS name (`up.sni`) so TLS SNI/cert-hostname
        // verification for https upstreams is unchanged, and the upstream `Host`
        // authority still comes from `ctx.up_host_header` (round-6 behavior). tls +
        // sni for https upstreams (OpenAI/S3); plaintext for bare host:port.
        let mut peer = HttpPeer::new(resolved, up.tls, up.sni.clone());
        peer.options.verify_cert = up.verify;
        peer.options.verify_hostname = up.verify;
        peer.options.connection_timeout = Some(Duration::from_secs(5));
        // Read timeout on the UPSTREAM connection (slowloris protection). Always
        // FINITE here — including for a WebSocket handshake — so the origin's
        // response header (the `101` or any non-101 fallback) and any fallback body
        // are bounded. The vendored H1 client relaxes this timeout to `None` for
        // the tunnel ONLY after it confirms a `101` upgrade (see
        // `vendor/pingora-core/src/protocols/http/v1/client.rs`), so a legitimately
        // idle established tunnel is not killed while a handshake that never
        // upgrades (or whose origin stalls) still times out. Deriving this from the
        // request-side upgrade flag would leave a non-101 fallback with no timeout.
        peer.options.read_timeout = loc.read_timeout.or(Some(Duration::from_secs(60)));
        peer.options.write_timeout = Some(Duration::from_secs(300));
        peer.options.idle_timeout = Some(Duration::from_secs(60));
        Ok(Box::new(peer))
    }

    /// On a connect failure, fail over: FIRST exhaust the current backend's other
    /// resolved addresses (a dual-stack/multi-A hostname whose first address is
    /// unreachable must still reach a healthy one), THEN advance to the next
    /// configured pool member. The whole thing is bounded by `MAX_CONNECT_ATTEMPTS`.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Ctx,
        mut e: Box<Error>,
    ) -> Box<Error> {
        ctx.attempts += 1;
        if ctx.attempts >= MAX_CONNECT_ATTEMPTS {
            // Out of budget — mark the backend down and give up (bounded 502).
            if !ctx.up_addr.is_empty() {
                self.mark_down(&ctx.up_addr);
            }
            return e;
        }

        // More resolved addresses for THIS backend? Try the next one WITHOUT marking
        // the whole hostname down (only one address failed) and without advancing the
        // configured-backend index.
        if ctx.addr_try + 1 < ctx.up_naddr {
            ctx.addr_try += 1;
            e.set_retry(true);
            return e;
        }

        // Every resolved address of this backend failed — NOW mark the configured
        // backend (`host:port`) down for the cooldown, then advance to the next pool
        // member if one exists (resetting the per-backend address index).
        if !ctx.up_addr.is_empty() {
            self.mark_down(&ctx.up_addr);
        }
        let cfg = ctx.cfg.clone();
        if let (Some(si), Some(li)) = (ctx.site, ctx.location) {
            if let Handler::Proxy(group) = &cfg.sites[si].locations[li].handler {
                if ctx.tries + 1 < group.servers.len() {
                    ctx.tries += 1;
                    ctx.addr_try = 0;
                    e.set_retry(true);
                }
            }
        }
        e
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        // RFC 9113 §8.2.3: an HTTP/2 request may legitimately carry MULTIPLE
        // `cookie` fields (each cookie-pair can be its own field for better HPACK
        // compression). An intermediary converting H2 → HTTP/1.1 MUST concatenate
        // them into ONE `Cookie` field joined by "; ". Sluice's ordinary upstreams
        // are HTTP/1.1, and Pingora's H2→H1 conversion forwards the split fields as
        // SEPARATE `Cookie` lines; many H1 stacks (RFC 6265's single-Cookie model)
        // read only the first, so session/CSRF cookies silently vanish. Repair it
        // here whenever the DOWNSTREAM is H2 (see `join_split_cookies`).
        if session.is_http2() {
            join_split_cookies(upstream_request)?;
        }
        let websocket = matches!((ctx.site, ctx.location), (Some(si), Some(li))
            if ctx.cfg.sites[si].locations[li].websocket);

        // Preserve a validated WebSocket upgrade ONLY for a location configured
        // for it: the client must have sent `Upgrade: websocket` and a
        // `Connection` naming `upgrade`. Snapshot it before we strip hop-by-hop
        // state, then reinstate a normalized pair below.
        let ws_upgrade = if websocket {
            let upgrade_val = upstream_request
                .headers
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .filter(|v| v.eq_ignore_ascii_case("websocket"))
                .map(str::to_owned);
            let conn_has_upgrade =
                connection_tokens(upstream_request).any(|t| t.eq_ignore_ascii_case("upgrade"));
            upgrade_val.filter(|_| conn_has_upgrade)
        } else {
            None
        };

        // Remove every header nominated by a `Connection` line (RFC 9110 §7.6.1:
        // these are strictly hop-by-hop and MUST NOT be forwarded), except the
        // framing headers Pingora owns and any routing header we set ourselves —
        // an attacker could otherwise use `Connection: X-Forwarded-Proto` to make
        // a conforming next hop delete a field the origin trusts, `Connection:
        // Host` to strip routing, or `Connection: Transfer-Encoding` to break the
        // body framing Pingora just chose (see the framing note below).
        let nominated: Vec<String> = connection_tokens(upstream_request)
            .map(|t| t.to_ascii_lowercase())
            .filter(|t| !matches!(t.as_str(), "host" | "content-length" | "transfer-encoding"))
            .collect();
        for name in &nominated {
            upstream_request.remove_header(name);
        }

        // Remove the standard client-supplied hop-by-hop set. NOTE: we must NOT
        // touch `Transfer-Encoding` / `Content-Length` here — this hook runs
        // AFTER Pingora has chosen the upstream body framing (and, for an HTTP/2
        // upload, just synthesized `Transfer-Encoding: chunked`); removing it
        // makes the upstream writer see a zero-length body and silently drop a
        // chunked upload. Pingora owns and re-derives that framing.
        for h in [
            "connection",
            "proxy-connection",
            "keep-alive",
            "te",
            "upgrade",
        ] {
            upstream_request.remove_header(h);
        }

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

        // Reinstate a single normalized WebSocket upgrade pair for ws locations.
        if let Some(up) = ws_upgrade {
            upstream_request.insert_header("Connection", "upgrade")?;
            upstream_request.insert_header("Upgrade", up.as_str())?;
        }

        // Replace Host with the single canonical value: the chosen upstream's
        // configured host for cross-host (https://) upstreams (OpenAI/S3 see
        // their own name), else the one canonical routed authority — never the
        // client's raw, possibly non-canonical Host. `insert_header` replaces any
        // existing Host, so no duplicate can reach the origin.
        let host_hdr = ctx
            .up_host_header
            .as_deref()
            .unwrap_or(ctx.authority.as_str());
        if !host_hdr.is_empty() {
            upstream_request.insert_header("Host", host_hdr)?;
        }

        // Forward the request target in canonical origin-form: the canonical path
        // the proxy validated (re-encoded to a valid target) plus the original
        // query. This is what makes the proxy and origin share ONE view — the raw
        // client target (absolute-form, backslashes, `..`, matrix params) is
        // never passed through.
        if !ctx.norm_path.is_empty() {
            let enc = encode_path_for_upstream(&ctx.norm_path);
            let pq = match upstream_request.uri.query() {
                Some(q) => format!("{enc}?{q}"),
                None => enc,
            };
            if let Ok(uri) = pq.parse::<http::Uri>() {
                upstream_request.set_uri(uri);
            }
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
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let cfg = ctx.cfg.clone();

        let status = upstream_response.status.as_u16();
        let method = session.req_header().method.clone();
        let may_have_body = response_may_have_body(status, &method);

        // A `101` (with a valid upgrade request) actually establishes the tunnel:
        // NOW relax the downstream tunnel timeouts / rate so the long-lived,
        // sparsely-read bidirectional stream isn't killed. A non-101 fallback keeps
        // the normal limits set in `request_filter`.
        if status == 101 && ctx.upgrade_request {
            session.set_read_timeout(None);
            session.set_min_send_rate(None);
            session.set_write_timeout(None);
        }
        // Whether this location transforms the body (sub-filter), which forces a
        // full, non-range representation (see the range handling below).
        let has_sub_filters = matches!((ctx.site, ctx.location), (Some(si), Some(li))
            if !cfg.sites[si].locations[li].sub_filters.is_empty());

        // Strip hop-by-hop headers the origin set before we forward (and before
        // caching) — the same sanitation applied to the request. A `101 Switching
        // Protocols` response is a WebSocket handshake, whose `Connection:
        // upgrade` / `Upgrade` pair is load-bearing, so it's left intact. As on
        // the request, we must NOT remove `Transfer-Encoding` / `Content-Length`
        // from a BODY-carrying response: this hook runs AFTER Pingora's
        // response-framing pass (which may have just synthesized
        // `Transfer-Encoding: chunked` for a bodied response with no length);
        // stripping it forces an EOF-delimited body while we still advertise
        // keepalive. Framing on a BODYLESS response is validated separately below.
        if status != 101 {
            let nominated: Vec<String> = upstream_response
                .headers
                .get_all("connection")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !matches!(t.as_str(), "" | "content-length" | "transfer-encoding"))
                .collect();
            for name in &nominated {
                upstream_response.remove_header(name);
            }
            for h in [
                "connection",
                "proxy-connection",
                "keep-alive",
                "te",
                "upgrade",
            ] {
                upstream_response.remove_header(h);
            }
        }

        // A `101 Switching Protocols` (or a successful `2xx` CONNECT, if ever
        // enabled) is NOT a bodyless HTTP message: what follows the header is the
        // UPGRADED byte stream (WebSocket frames / tunnel), which Pingora delivers
        // through the SAME `response_body_filter` as `HttpTask::UpgradedBody`. We
        // must let those bytes pass through untouched — suppressing them would
        // black-hole every WebSocket connection.
        let is_upgrade = is_protocol_upgrade(status, &method);

        // A response that cannot carry a message body — 1xx, 204, 205, 304, any
        // HEAD response — MUST NOT be followed by content, and must not advertise
        // a body via framing headers. Two parts:
        //  (a) discard ALL upstream body bytes (`suppress_body`): Pingora 0.8 does
        //      not itself classify e.g. `205` as bodyless, so an origin `205
        //      Content-Length: 3` + `abc` would otherwise leak `abc` after the
        //      header — desyncing a downstream parser that ends a 205 at its
        //      headers. Enforced in `response_body_filter`. NOT set for an upgrade
        //      (that "body" is the upgraded stream, above).
        //  (b) make the header framing self-consistent by STATUS (status
        //      prohibitions win over the request method): a stray
        //      `Transfer-Encoding` (no terminating chunk) or an inconsistent
        //      `Content-Length` is a smuggling differential.
        ctx.suppress_body = !may_have_body && !is_upgrade;
        if !may_have_body {
            // Transfer-Encoding is never legal without a body.
            upstream_response.remove_header("Transfer-Encoding");
            match bodyless_content_length(status, &method) {
                BodylessCl::Remove => {
                    upstream_response.remove_header("Content-Length");
                }
                BodylessCl::Keep => {}
                BodylessCl::ZeroLength => {
                    // Explicit canonical zero-length framing (else H1
                    // close-delimits it, breaking keep-alive, and H2 emits a DATA
                    // frame). The origin's bytes are dropped by `suppress_body`.
                    upstream_response.remove_header("Content-Length");
                    upstream_response.insert_header("Content-Length", "0")?;
                }
            }
        }

        // `response_filter` is called for EVERY response header on this request,
        // including 1xx informational (100/103) headers that precede the final
        // one. Only a FINAL response can carry a representation body and be
        // rewritten; do nothing rewrite-related for an interim 1xx (and never let
        // a text 1xx leave `ctx.rewrite` set for a later binary final response).
        // (Framing on those was already sanitized above.)
        if (100..=199).contains(&status) {
            return Ok(());
        }

        if let Some(idx) = ctx.site {
            if let Some(hsts) = &cfg.sites[idx].hsts {
                upstream_response.insert_header("Strict-Transport-Security", hsts.as_str())?;
            }
        }

        // Byte ranges are incompatible with a length-changing body transform: a
        // range of the ORIGINAL bytes, once rewritten, no longer matches the
        // advertised `Content-Range`/length (corruption — verified on origin 206
        // and on range cache hits). We already stripped `Range`/`If-Range` from
        // the request, so the origin/cache return the FULL representation (a 200).
        // For a sub-filter location: stop advertising range support (`Accept-
        // Ranges`), and if the origin still returns a partial `206` (a protocol
        // violation for a non-range request) we pass it through UNTRANSFORMED
        // below rather than corrupt a partial body — so its `Content-Range` is
        // kept; on any non-206 a stray `Content-Range` is dropped.
        if has_sub_filters {
            upstream_response.remove_header("Accept-Ranges");
            if status != 206 {
                upstream_response.remove_header("Content-Range");
            }
        }

        // This is the final response: decide body rewriting FRESH. Clear any state
        // and never carry a decision across responses.
        ctx.rewrite = false;
        ctx.rewrite_carry.clear();

        // Enable response-body rewriting only for a final response that (a) is
        // allowed to carry a body — excludes 101/upgrades, 204/205/304, HEAD, and a
        // successful CONNECT tunnel; setting chunked/removing length on those is a
        // framing violation and corrupts an upgraded byte stream — (b) is NOT a
        // partial `206` (transforming a byte range corrupts the representation;
        // ranges are already disabled for this location, so a 206 is a stray
        // origin partial we pass through as-is), and (c) is an uncompressed text
        // response (the origin was asked not to compress above).
        if let (Some(si), Some(li)) = (ctx.site, ctx.location) {
            let loc = &cfg.sites[si].locations[li];
            if may_have_body && status != 206 && !loc.sub_filters.is_empty() {
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
                    // The body is about to change: drop Content-Length and every
                    // now-stale integrity/validator header.
                    for h in [
                        "Content-Length",
                        "Content-MD5",
                        "Digest",
                        "Content-Digest",
                        "Repr-Digest",
                        "ETag",
                    ] {
                        upstream_response.remove_header(h);
                    }
                    // Removing Content-Length leaves the response with no framing,
                    // and this hook runs AFTER Pingora's response-framing pass — so
                    // we must supply the framing ourselves or the downstream body
                    // becomes EOF-delimited while we still advertise keep-alive.
                    // Transfer-Encoding is not stripped above, so remove any stale
                    // one first, then set the canonical framing per downstream
                    // protocol:
                    upstream_response.remove_header("Transfer-Encoding");
                    if session.is_http2() {
                        // HTTP/2 has no Transfer-Encoding; the body is framed by
                        // DATA + END_STREAM. Nothing to add.
                    } else if session.req_header().version == http::Version::HTTP_10 {
                        // HTTP/1.0 has no chunked encoding: the only way to delimit
                        // an unknown-length body is to close the connection at EOF.
                        session.set_keepalive(None);
                    } else {
                        // HTTP/1.1: stream the rewritten body chunked.
                        upstream_response.insert_header("Transfer-Encoding", "chunked")?;
                    }
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
        // Bodyless response (204/205/304/1xx/HEAD, or a stray body on any of them):
        // drop every byte so nothing follows the header section on the wire. The
        // upstream body is still fully read by Pingora (draining its framing), so
        // the upstream connection stays reusable; we just never forward it.
        if ctx.suppress_body {
            *body = None;
            return Ok(None);
        }
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
        let (emit, carry) =
            rewrite_stream(&data, &loc.sub_filters, loc.sub_max_from, end_of_stream);
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
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);
        // Only a matched site becomes a metric label; an unmatched (attacker-
        // controlled) Host is collapsed to "-" so it can't inflate cardinality.
        let host = if ctx.site.is_some() {
            ctx.host.as_str()
        } else {
            "-"
        };
        let elapsed = ctx.start.elapsed();

        REQUESTS
            .with_label_values(&[host, &format!("{}xx", status / 100)])
            .inc();
        RESPONSES
            .with_label_values(&[host, &status.to_string()])
            .inc();
        LATENCY
            .with_label_values(&[host])
            .observe(elapsed.as_secs_f64());
        RESP_BYTES
            .with_label_values(&[host])
            .inc_by(session.body_bytes_sent() as u64);
        REQ_BYTES
            .with_label_values(&[host])
            .inc_by(session.body_bytes_read() as u64);
        if e.is_some() || matches!(status, 502..=504) {
            UPSTREAM_ERRORS.with_label_values(&[host]).inc();
        }
        let country_metric = ctx
            .cfg
            .geoip
            .as_ref()
            .is_some_and(|g| g.metric_labels.iter().any(|l| l == "country"));
        if country_metric && !ctx.country.is_empty() {
            REQUESTS_BY_COUNTRY
                .with_label_values(&[ctx.country.as_str()])
                .inc();
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

        let client = if ctx.client_ip.is_empty() {
            "-"
        } else {
            ctx.client_ip.as_str()
        };
        let method = session.req_header().method.as_str().to_owned();
        let path = session.req_header().uri.path().to_owned();
        let err = e.map(|e| format!(" err={e}")).unwrap_or_default();
        let up = if ctx.up_addr.is_empty() {
            "-"
        } else {
            ctx.up_addr.as_str()
        };
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
        // Redirect to https, but only for a Host we actually serve. An
        // unrecognized or ambiguous Host gets 400 rather than a 301 to an
        // arbitrary location, so :80 can't be used as an open redirector.
        let host = routed_authority(session)
            .map(|a| a.host().to_string())
            .unwrap_or_default();
        let cfg = self.cfg.load();
        let known = !host.is_empty() && cfg.index.contains_key(&host);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SubFilter;

    #[test]
    fn normalize_defeats_encoding_and_traversal() {
        assert_eq!(normalize_path("/a/../b").as_deref(), Some("/b"));
        assert_eq!(normalize_path("//admin").as_deref(), Some("/admin"));
        assert_eq!(normalize_path("/%61dmin").as_deref(), Some("/admin"));
        assert_eq!(normalize_path("/a/./b/").as_deref(), Some("/a/b/"));
        assert_eq!(
            normalize_path("/x/../../etc/passwd").as_deref(),
            Some("/etc/passwd")
        );
        assert!(normalize_path("/a\u{0}b").is_none()); // NUL rejected
                                                       // MULTI-encoding must collapse to the SAME canonical view (the round-10
                                                       // bypass): `/%2e%2e/admin` and `/%252e%252e/admin` both → `/admin`, and
                                                       // `/adm%2569n` (→ %69 → i) → `/admin`. So WAF/deny/routing can't be
                                                       // slipped by a deeper origin-side decode.
        assert_eq!(normalize_path("/%2e%2e/admin").as_deref(), Some("/admin"));
        assert_eq!(
            normalize_path("/%252e%252e/admin").as_deref(),
            Some("/admin")
        );
        assert_eq!(
            normalize_path("/%25252e%25252e/admin").as_deref(),
            Some("/admin")
        );
        assert_eq!(normalize_path("/adm%2569n").as_deref(), Some("/admin"));
        // Encoded slash decodes and splits (segment can't hide a traversal).
        assert_eq!(normalize_path("/a%2f..%2fadmin").as_deref(), Some("/admin"));
        // Pathologically over-encoded / over-long → fail closed (400).
        assert!(normalize_path(&("%25".repeat(9000))).is_none());
        // MALFORMED percent-encoding must fail closed (was passed through as
        // "stable", letting a lenient origin re-read `/admin%` as `/admin`).
        assert!(normalize_path("/admin%").is_none());
        assert!(normalize_path("/admin%2").is_none());
        assert!(normalize_path("/admin%zz").is_none());
        assert!(normalize_path("/admin%2z").is_none());
        // `%25` (encoded percent) → literal `%`, which is ALSO ambiguous to a
        // lenient origin → fail closed.
        assert!(normalize_path("/admin%25").is_none());
        // A well-formed multi-encoding still decodes cleanly (no literal % left).
        assert_eq!(normalize_path("/foo%2541").as_deref(), Some("/fooA"));
    }

    #[test]
    fn normalize_rejects_backslash_and_strips_path_params() {
        // Backslashes (raw or via %5c / %255c) are rejected — a Windows/IIS-style
        // origin would treat them as separators the proxy never saw.
        assert!(normalize_path("/a\\b").is_none());
        assert!(normalize_path("/a%5cb").is_none());
        assert!(normalize_path("/a%255cb").is_none());
        assert!(normalize_path("/admin\\..\\secret").is_none());
        // Path (matrix) parameters are dropped per segment, the way servlet/Spring
        // origins route — so `/admin;anything` canonicalizes to `/admin` and can't
        // slip past a protected `location "/admin"` into a public catch-all.
        assert_eq!(normalize_path("/admin;foo=bar").as_deref(), Some("/admin"));
        assert_eq!(normalize_path("/admin;/x").as_deref(), Some("/admin/x"));
        assert_eq!(
            normalize_path("/a/b;jsessionid=9/c").as_deref(),
            Some("/a/b/c")
        );
        // A leading `;` yields an empty (collapsed) segment.
        assert_eq!(normalize_path("/;evil/admin").as_deref(), Some("/admin"));
    }

    #[test]
    fn parse_authority_rejects_ambiguous_forms() {
        // Valid, canonicalized (lowercased).
        assert_eq!(
            parse_authority("Example.COM").as_ref().map(|a| a.as_str()),
            Some("example.com")
        );
        assert_eq!(
            parse_authority("example.com:8080")
                .as_ref()
                .map(|a| a.as_str()),
            Some("example.com:8080")
        );
        // Non-numeric / empty / over-range port → rejected (the `split(':')` bug
        // let `host:evil` through as `host`).
        assert!(parse_authority("example.com:evil").is_none());
        assert!(parse_authority("example.com:").is_none());
        assert!(parse_authority("example.com:99999").is_none());
        // Userinfo and paths are never valid routing authorities.
        assert!(parse_authority("user@example.com").is_none());
        assert!(parse_authority("example.com/path").is_none());
        assert!(parse_authority("").is_none());
        assert!(parse_authority("   ").is_none());
    }

    #[test]
    fn encode_path_round_trips_to_canonical() {
        // The decoded canonical path is re-encoded to a valid target that decodes
        // ONCE back to itself — a literal `%`, space, and non-ASCII are escaped;
        // `/` and pchars stay literal.
        assert_eq!(encode_path_for_upstream("/a b"), "/a%20b");
        assert_eq!(encode_path_for_upstream("/100%off"), "/100%25off");
        assert_eq!(encode_path_for_upstream("/a/b-c_d.e~f"), "/a/b-c_d.e~f");
        assert_eq!(encode_path_for_upstream("/café"), "/caf%C3%A9");
    }

    #[test]
    fn conn_limiter_established_is_exact_and_releases_on_close() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let lim = Arc::new(ConnLimiter::new(2));
        assert_eq!(lim.established(ip), 0);

        // Two established slots granted (via post-handshake promote); the third is
        // refused while both are held.
        let g1 = lim.promote(ip).expect("1st slot");
        let g2 = lim.promote(ip).expect("2nd slot");
        assert_eq!(lim.established(ip), 2);
        assert!(lim.promote(ip).is_none(), "3rd concurrent conn refused");

        // Closing a connection (guard drop) frees the slot IMMEDIATELY — not after
        // a time window: a new one is admitted right away.
        drop(g1);
        assert_eq!(lim.established(ip), 1);
        let g3 = lim
            .promote(ip)
            .expect("slot freed by close is reusable at once");
        assert_eq!(lim.established(ip), 2);

        // When all close, the per-IP entry is pruned (bounded memory under churn).
        drop(g2);
        drop(g3);
        assert_eq!(lim.established(ip), 0);
        assert!(!lim.state.contains_key(&ip), "empty entry pruned");

        // A different IP has its own independent budget.
        let other: IpAddr = "203.0.113.8".parse().unwrap();
        let _o1 = lim.promote(other).unwrap();
        let _o2 = lim.promote(other).unwrap();
        assert!(lim.promote(other).is_none());
        assert_eq!(lim.established(ip), 0);
    }

    #[test]
    fn conn_limiter_counts_pending_before_handshake() {
        // The reviewer's scenario: with cap 1, a first connection stalled in the
        // TLS handshake (admitted pre-handshake, never promoted) must make a
        // SECOND pre-handshake connection from the same IP be refused at accept —
        // pre-handshake sockets count against the cap, not just established ones.
        let ip: IpAddr = "198.51.100.9".parse().unwrap();
        let lim = Arc::new(ConnLimiter::new(1));

        assert!(lim.admit_pending(ip), "1st pre-handshake conn admitted");
        assert_eq!(lim.in_flight(ip), 1);
        assert!(
            !lim.admit_pending(ip),
            "2nd pre-handshake conn refused while the 1st is still handshaking"
        );

        // The admitted connection completes its handshake: promote converts the
        // pending slot to an established one (still exactly 1 in-flight).
        let g = lim.promote(ip).expect("promote the admitted pending conn");
        assert_eq!(lim.in_flight(ip), 1);
        assert_eq!(lim.established(ip), 1);
        // Still capped while it's established.
        assert!(!lim.admit_pending(ip));

        // Close it → a fresh connection is admitted at once.
        drop(g);
        assert_eq!(lim.in_flight(ip), 0);
        assert!(lim.admit_pending(ip));
    }

    #[test]
    fn conn_limiter_pending_expires_by_ttl() {
        // A pending slot from an abandoned handshake self-heals: after the TTL it
        // no longer blocks new connections (no permanent leak).
        let ip: IpAddr = "198.51.100.10".parse().unwrap();
        let mut lim = ConnLimiter::new(1);
        lim.pending_ttl = Duration::from_millis(50);
        let lim = Arc::new(lim);

        assert!(lim.admit_pending(ip));
        assert!(!lim.admit_pending(ip), "capped while pending is fresh");
        std::thread::sleep(Duration::from_millis(70));
        assert!(
            lim.admit_pending(ip),
            "stale pending pruned; new conn admitted"
        );
    }

    #[test]
    fn conn_limiter_aggregates_ipv6_by_64() {
        // Two addresses in the SAME /64 must share one budget (a subscriber can
        // pick any interface-identifier bits), while a DIFFERENT /64 is independent.
        let a: IpAddr = "2001:db8:abcd:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:abcd:1:ffff:ffff:ffff:ffff".parse().unwrap(); // same /64 as a
        let other: IpAddr = "2001:db8:abcd:2::1".parse().unwrap(); // different /64
        let lim = Arc::new(ConnLimiter::new(1));

        // Pending budget is shared within the /64.
        assert!(lim.admit_pending(a), "1st addr in /64 admitted");
        assert!(
            !lim.admit_pending(b),
            "2nd addr in same /64 must be refused — shared budget"
        );
        // A different /64 has its own budget.
        assert!(lim.admit_pending(other), "different /64 admitted");
        // Exactly two distinct keys are tracked (the /64 and the other /64).
        assert_eq!(lim.entry_count(), 2);

        // Established budget is also shared within the /64: promote `a`, then a
        // fresh connection from `b` (same /64) is refused; its close frees it.
        let lim2 = Arc::new(ConnLimiter::new(1));
        let g = lim2.promote(a).expect("promote a");
        assert_eq!(lim2.established(b), 1, "established count keyed by /64");
        assert!(
            lim2.promote(b).is_none(),
            "same /64 shares established budget"
        );
        drop(g);
        assert!(lim2.promote(b).is_some(), "slot freed for the shared /64");
    }

    #[test]
    fn conn_limiter_sweep_reclaims_without_return_visit() {
        // The leak the reviewer found: an abandoned pending slot from an IP that
        // NEVER returns must still be reclaimed (entry + Vec removed) by the global
        // sweep — not only when that same IP calls admit/promote again.
        let gone: IpAddr = "203.0.113.99".parse().unwrap();
        let mut lim = ConnLimiter::new(1);
        lim.pending_ttl = Duration::from_millis(40);
        let lim = Arc::new(lim);

        assert!(lim.admit_pending(gone));
        assert_eq!(lim.entry_count(), 1);
        std::thread::sleep(Duration::from_millis(60));
        // The IP never comes back; a global sweep reclaims its stale entry.
        lim.sweep_expired(Instant::now());
        assert_eq!(lim.entry_count(), 0, "stale entry fully removed by sweep");
    }

    #[test]
    fn conn_limiter_global_table_bound() {
        // Defense in depth: once the table is at its ceiling, a brand-new source
        // key is refused pre-handshake (rather than growing memory unbounded).
        let mut lim = ConnLimiter::new(4);
        lim.max_entries = 2;
        let lim = Arc::new(lim);
        assert!(lim.admit_pending("198.51.100.1".parse().unwrap()));
        assert!(lim.admit_pending("198.51.100.2".parse().unwrap()));
        assert_eq!(lim.entry_count(), 2);
        // A third distinct source with the table full → refused.
        assert!(!lim.admit_pending("198.51.100.3".parse().unwrap()));
        // But an EXISTING key can still add another in-flight slot (no new entry).
        assert!(lim.admit_pending("198.51.100.1".parse().unwrap()));
    }

    #[test]
    fn response_may_have_body_excludes_bodyless_and_informational() {
        use http::Method;
        // Bodied final responses on a GET → rewritable.
        assert!(response_may_have_body(200, &Method::GET));
        assert!(response_may_have_body(404, &Method::GET));
        // Informational (incl. 101 upgrade), 204, 205, 304 → no body.
        assert!(!response_may_have_body(100, &Method::GET));
        assert!(!response_may_have_body(103, &Method::GET));
        assert!(!response_may_have_body(101, &Method::GET));
        assert!(!response_may_have_body(204, &Method::GET));
        assert!(!response_may_have_body(205, &Method::GET)); // Reset Content: no body
        assert!(!response_may_have_body(304, &Method::GET));
        // HEAD never has a body regardless of status.
        assert!(!response_may_have_body(200, &Method::HEAD));
        // Successful CONNECT is a tunnel, no body; a failed CONNECT does have one.
        assert!(!response_may_have_body(200, &Method::CONNECT));
        assert!(response_may_have_body(405, &Method::CONNECT));
    }

    #[test]
    fn bodyless_content_length_status_prohibitions_win_over_method() {
        use http::Method;
        use BodylessCl::*;
        // 1xx and 204: Content-Length forbidden — removed REGARDLESS of method
        // (the bug kept it whenever the request was HEAD).
        assert_eq!(bodyless_content_length(103, &Method::GET), Remove);
        assert_eq!(bodyless_content_length(103, &Method::HEAD), Remove);
        assert_eq!(bodyless_content_length(204, &Method::GET), Remove);
        assert_eq!(bodyless_content_length(204, &Method::HEAD), Remove);
        // 205: canonical zero-length (bodyless, Pingora doesn't special-case it);
        // even for a HEAD request the status prohibition wins → NOT "kept".
        assert_eq!(bodyless_content_length(205, &Method::GET), ZeroLength);
        assert_eq!(bodyless_content_length(205, &Method::HEAD), ZeroLength);
        // 304: legal representation metadata — kept.
        assert_eq!(bodyless_content_length(304, &Method::GET), Keep);
        assert_eq!(bodyless_content_length(304, &Method::HEAD), Keep);
        // HEAD of a body-carrying status (200/404/3xx): Content-Length is the
        // length the GET body would have — kept.
        assert_eq!(bodyless_content_length(200, &Method::HEAD), Keep);
        assert_eq!(bodyless_content_length(404, &Method::HEAD), Keep);
        // A successful CONNECT tunnel MUST NOT carry Content-Length (RFC 9110
        // §9.3.6) — remove it, never synthesize a zero. A failed CONNECT (4xx/5xx)
        // is an ordinary error response with a body.
        assert_eq!(bodyless_content_length(200, &Method::CONNECT), Remove);
    }

    #[test]
    fn is_protocol_upgrade_covers_101_and_2xx_connect_only() {
        use http::Method;
        // 101 and a successful 2xx CONNECT are upgrades → their "body" is the
        // upgraded stream and must pass through (never suppressed/rewritten).
        assert!(is_protocol_upgrade(101, &Method::GET));
        assert!(is_protocol_upgrade(200, &Method::CONNECT));
        assert!(is_protocol_upgrade(299, &Method::CONNECT));
        // Ordinary bodyless statuses are NOT upgrades — their body is suppressed.
        assert!(!is_protocol_upgrade(204, &Method::GET));
        assert!(!is_protocol_upgrade(205, &Method::GET));
        assert!(!is_protocol_upgrade(304, &Method::GET));
        assert!(!is_protocol_upgrade(103, &Method::GET));
        // A failed CONNECT (non-2xx) is an ordinary error response, not a tunnel.
        assert!(!is_protocol_upgrade(405, &Method::CONNECT));
        // A plain 200 GET is a normal body, not an upgrade.
        assert!(!is_protocol_upgrade(200, &Method::GET));
    }

    #[test]
    fn request_wants_upgrade_detects_upgrade_intent() {
        use pingora::http::RequestHeader;
        let mk = |hdrs: &[(&str, &str)]| {
            let mut r = RequestHeader::build("GET", b"/", None).unwrap();
            for (k, v) in hdrs {
                r.append_header(k.to_string(), *v).unwrap();
            }
            r
        };
        // A WebSocket handshake: Connection: Upgrade + Upgrade: websocket.
        assert!(request_wants_upgrade(&mk(&[
            ("Connection", "Upgrade"),
            ("Upgrade", "websocket"),
        ])));
        // Either header alone is enough to signal upgrade intent (fail safe).
        assert!(request_wants_upgrade(&mk(&[("Upgrade", "websocket")])));
        assert!(request_wants_upgrade(&mk(&[(
            "Connection",
            "keep-alive, Upgrade"
        )])));
        // Case-insensitive token match.
        assert!(request_wants_upgrade(&mk(&[("Connection", "upgrade")])));
        // An ordinary request is not an upgrade.
        assert!(!request_wants_upgrade(&mk(&[("Connection", "keep-alive")])));
        assert!(!request_wants_upgrade(&mk(&[])));
    }

    #[test]
    fn is_websocket_upgrade_request_requires_rfc6455_shape() {
        use pingora::http::RequestHeader;
        // The RFC 6455 example key ("the sample nonce", 16 bytes base64-encoded).
        const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
        // Build a request from method + header list; version defaults to HTTP/1.1.
        let mk = |method: &str, hdrs: &[(&str, &str)]| {
            let mut r = RequestHeader::build(method, b"/", None).unwrap();
            for (k, v) in hdrs {
                r.append_header(k.to_string(), *v).unwrap();
            }
            r
        };
        // The four handshake headers a valid GET must carry.
        let full: &[(&str, &str)] = &[
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", KEY),
        ];

        // A complete, well-formed handshake is accepted (case-insensitive tokens,
        // extra Connection tokens allowed).
        assert!(is_websocket_upgrade_request(&mk("GET", full)));
        assert!(is_websocket_upgrade_request(&mk(
            "GET",
            &[
                ("Upgrade", "WebSocket"),
                ("Connection", "keep-alive, upgrade"),
                ("Sec-WebSocket-Version", "13"),
                ("Sec-WebSocket-Key", KEY),
            ]
        )));

        // Wrong method or version → not a handshake (an upgrade-shaped POST is the
        // core bypass we reject).
        assert!(!is_websocket_upgrade_request(&mk("POST", full)));
        {
            let mut r = mk("GET", full);
            r.set_version(http::Version::HTTP_10);
            assert!(!is_websocket_upgrade_request(&r));
        }

        // Missing any single required header → rejected.
        for drop in 0..full.len() {
            let subset: Vec<(&str, &str)> = full
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != drop)
                .map(|(_, kv)| *kv)
                .collect();
            assert!(
                !is_websocket_upgrade_request(&mk("GET", &subset)),
                "missing field #{drop} must be rejected"
            );
        }

        // Wrong Sec-WebSocket-Version (not 13) → rejected.
        assert!(!is_websocket_upgrade_request(&mk(
            "GET",
            &[
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Version", "8"),
                ("Sec-WebSocket-Key", KEY),
            ]
        )));

        // Malformed keys (wrong length / bad padding / illegal chars / empty) → rejected.
        for bad_key in ["AAAA", "", "not-base64!!padding======", &"A".repeat(24)] {
            assert!(
                !is_websocket_upgrade_request(&mk(
                    "GET",
                    &[
                        ("Upgrade", "websocket"),
                        ("Connection", "Upgrade"),
                        ("Sec-WebSocket-Version", "13"),
                        ("Sec-WebSocket-Key", bad_key),
                    ]
                )),
                "bad key {bad_key:?} must be rejected"
            );
        }

        // `Upgrade: h2c` (or any non-websocket) is not a WebSocket upgrade.
        assert!(!is_websocket_upgrade_request(&mk(
            "GET",
            &[
                ("Upgrade", "h2c"),
                ("Connection", "upgrade"),
                ("Sec-WebSocket-Version", "13"),
                ("Sec-WebSocket-Key", KEY),
            ]
        )));
        // An ordinary request (e.g. a slow-drip POST routed to a ws location) is
        // NOT exempt from deadlines.
        assert!(!is_websocket_upgrade_request(&mk(
            "GET",
            &[("Content-Type", "text/plain")]
        )));
    }

    #[test]
    fn websocket_key_shape_validation() {
        // The RFC 6455 example key.
        assert!(is_valid_websocket_key("dGhlIHNhbXBsZSBub25jZQ=="));
        // 24 chars, valid alphabet, `==` padding.
        assert!(is_valid_websocket_key("AAAAAAAAAAAAAAAAAAAAAA=="));
        assert!(is_valid_websocket_key("abcd/EFGh+ijkLMNOpqrST=="));
        // Wrong length.
        assert!(!is_valid_websocket_key(""));
        assert!(!is_valid_websocket_key("AAAA"));
        assert!(!is_valid_websocket_key("AAAAAAAAAAAAAAAAAAAAAA==="));
        // Missing / wrong padding.
        assert!(!is_valid_websocket_key("AAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(!is_valid_websocket_key("=AAAAAAAAAAAAAAAAAAAAA=="));
        // Illegal character in the data section.
        assert!(!is_valid_websocket_key("AAAA!AAAAAAAAAAAAAAAAA=="));
    }

    #[test]
    fn join_split_cookies_concatenates_h2_fields_with_semicolon_space() {
        use pingora::http::RequestHeader;
        let mk = |cookies: &[&str]| {
            let mut r = RequestHeader::build("GET", b"/", None).unwrap();
            for c in cookies {
                r.append_header("cookie", *c).unwrap();
            }
            r
        };
        let cookie_lines = |r: &RequestHeader| -> Vec<String> {
            r.headers
                .get_all("cookie")
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect()
        };

        // Two split fields → one joined field with exactly "; ", order preserved.
        let mut r = mk(&["first=one", "second=two"]);
        join_split_cookies(&mut r).unwrap();
        assert_eq!(cookie_lines(&r), vec!["first=one; second=two".to_string()]);

        // Three fields, order preserved, byte-exact values (incl. `=` and spaces
        // inside a value are not introduced/removed beyond the "; " join).
        let mut r = mk(&["a=1", "b=2", "c=3"]);
        join_split_cookies(&mut r).unwrap();
        assert_eq!(cookie_lines(&r), vec!["a=1; b=2; c=3".to_string()]);

        // A SINGLE field is left exactly as-is (no trailing separator, no rewrite).
        let mut r = mk(&["only=1"]);
        join_split_cookies(&mut r).unwrap();
        assert_eq!(cookie_lines(&r), vec!["only=1".to_string()]);

        // No cookie at all → still a no-op, no header introduced.
        let mut r = mk(&[]);
        join_split_cookies(&mut r).unwrap();
        assert!(cookie_lines(&r).is_empty());
    }

    #[test]
    fn validate_content_length_rejects_duplicates_and_noncanonical() {
        use pingora::http::RequestHeader;
        let mk = |cls: &[&str]| {
            let mut r = RequestHeader::build("POST", b"/", None).unwrap();
            for c in cls {
                r.append_header("content-length", *c).unwrap();
            }
            r
        };

        // Absent → fine.
        assert_eq!(validate_content_length(&mk(&[])), ContentLength::Absent);

        // Exactly one canonical value → parsed.
        assert_eq!(validate_content_length(&mk(&["0"])), ContentLength::One(0));
        assert_eq!(
            validate_content_length(&mk(&["45"])),
            ContentLength::One(45)
        );
        assert_eq!(
            validate_content_length(&mk(&["18446744073709551615"])), // u64::MAX
            ContentLength::One(u64::MAX)
        );

        // The core smuggling vector: two DIFFERING fields → reject.
        assert_eq!(
            validate_content_length(&mk(&["45", "4"])),
            ContentLength::Invalid
        );
        // EQUAL duplicates are also rejected (sum-vs-dedup parser differential).
        assert_eq!(
            validate_content_length(&mk(&["4", "4"])),
            ContentLength::Invalid
        );

        // Non-canonical single values → reject.
        for bad in [
            "4, 4",                 // comma-folded duplicate in one field
            " 4",                   // leading space
            "4 ",                   // trailing space
            "+4",                   // sign
            "-4",                   // sign
            "0x4",                  // hex
            "04",                   // leading zero
            "4.0",                  // decimal point
            "",                     // empty
            "18446744073709551616", // u64::MAX + 1 (overflow)
        ] {
            assert_eq!(
                validate_content_length(&mk(&[bad])),
                ContentLength::Invalid,
                "non-canonical CL {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn request_has_credentials_detects_auth_and_cookie() {
        use pingora::http::RequestHeader;
        let with = |k: &str, v: &str| {
            let mut r = RequestHeader::build("GET", b"/", None).unwrap();
            r.append_header(k.to_string(), v.to_string()).unwrap();
            r
        };
        assert!(request_has_credentials(&with(
            "authorization",
            "Bearer secret"
        )));
        assert!(request_has_credentials(&with("cookie", "session=secret")));
        // A plain GET with neither is not credentialed.
        let plain = RequestHeader::build("GET", b"/", None).unwrap();
        assert!(!request_has_credentials(&plain));
        // Case-insensitive header lookup (HeaderMap is case-insensitive).
        assert!(request_has_credentials(&with("Authorization", "x")));
        assert!(request_has_credentials(&with("Cookie", "a=b")));
    }

    // (Upstream DNS resolution — IP-literal bypass, TTL cache, singleflight, bounded
    // concurrency, serve-stale, and bounded-502-on-failure — is unit-tested in
    // `crate::dns`. Multi-address failover is exercised end-to-end in
    // `tests/upstream_dns_failover.rs`.)

    #[test]
    fn max_body_does_not_apply_to_an_established_tunnel() {
        use std::time::Duration;
        let long_deadline = Duration::from_secs(30);
        let limit = Some(4u64); // a 4-byte `max-body`, as in the reviewer's repro

        // Ordinary request: cumulative body bytes over the limit are rejected. The
        // first 4 bytes fit; the 5th pushes cumulative to 5 > 4.
        assert_eq!(
            request_body_decision(false, Duration::ZERO, long_deadline, limit, 0, 4),
            BodyDecision::Continue(4)
        );
        assert_eq!(
            request_body_decision(false, Duration::ZERO, long_deadline, limit, 4, 1),
            BodyDecision::MaxBodyExceeded
        );

        // Established tunnel (`was_upgraded == true`): the SAME 5th byte — and any
        // amount of cumulative tunnel traffic far beyond `max-body` — is allowed,
        // and `body_seen` is not advanced (tunnel frames are not an HTTP entity).
        assert_eq!(
            request_body_decision(true, Duration::ZERO, long_deadline, limit, 4, 1),
            BodyDecision::Continue(4)
        );
        assert_eq!(
            request_body_decision(
                true,
                Duration::ZERO,
                long_deadline,
                limit,
                1_000_000,
                65_536
            ),
            BodyDecision::Continue(1_000_000)
        );
    }

    #[test]
    fn request_body_decision_enforces_deadline_and_limit_before_upgrade() {
        use std::time::Duration;
        let deadline = Duration::from_secs(3);

        // Deadline reached (`>=`) on a non-upgraded request → rejected, regardless
        // of body size.
        assert_eq!(
            request_body_decision(false, deadline, deadline, None, 0, 0),
            BodyDecision::DeadlineExceeded
        );
        // A confirmed tunnel is NOT bound by the assembly deadline even long past it.
        assert_eq!(
            request_body_decision(true, Duration::from_secs(3600), deadline, None, 0, 0),
            BodyDecision::Continue(0)
        );
        // No configured limit → body bytes just accumulate without a cap.
        assert_eq!(
            request_body_decision(false, Duration::ZERO, deadline, None, 10, 90),
            BodyDecision::Continue(10)
        );
        // Within budget → cumulative count advances.
        assert_eq!(
            request_body_decision(false, Duration::ZERO, deadline, Some(100), 10, 40),
            BodyDecision::Continue(50)
        );
    }

    #[test]
    fn accept_encoding_key_distinguishes_qvalue_and_order() {
        let k = |s: &str| accept_encoding_key(std::iter::once(s.as_bytes()));
        // The reviewer's collisions: same token set, different q-weights / order,
        // which the origin can legitimately negotiate differently. Must NOT share
        // a key.
        assert_ne!(k("br;q=.1, gzip;q=1"), k("br;q=1, gzip;q=.1"));
        // q=0.000 (a valid zero weight the old parser missed) differs from no q.
        assert_ne!(k("gzip"), k("gzip;q=0.000"));
        // Identical bytes still collapse to one key (real cache hit).
        assert_eq!(k("gzip, br"), k("gzip, br"));
        // Multiple header lines are boundary-separated (not concatenated blindly).
        let two = accept_encoding_key(["gzip".as_bytes(), "br".as_bytes()].into_iter());
        assert_ne!(two, k("gzipbr"));
    }

    #[test]
    fn active_health_key_separates_pools_sharing_a_backend() {
        let addr = "10.0.0.1:8080";
        // Same backend, different sites → independent health verdicts.
        assert_ne!(
            active_health_key("a.example", 0, addr),
            active_health_key("b.example", 0, addr)
        );
        // Same site, different locations → independent too.
        assert_ne!(
            active_health_key("a.example", 0, addr),
            active_health_key("a.example", 1, addr)
        );
        assert_eq!(
            active_health_key("a.example", 0, addr),
            active_health_key("a.example", 0, addr)
        );
    }

    #[test]
    #[cfg(unix)]
    fn docroot_fd_serves_real_files_and_refuses_symlink_escape() {
        let base0 = std::env::temp_dir().join(format!("sluice-static-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base0);
        std::fs::create_dir_all(&base0).unwrap();
        let base = std::fs::canonicalize(&base0).unwrap(); // macOS /var symlink
        let root = base.join("www");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("ok.txt"), b"public").unwrap();
        std::fs::write(base.join("secret"), b"TOPSECRET").unwrap();

        // Pin the docroot by fd (as config load does).
        let rf = crate::dirs::SecureDir::open_ro(root.to_str().unwrap()).unwrap();
        // A real file under root opens and reports the correct length.
        let f = rf.open_file_under(&["ok.txt".to_string()]).unwrap();
        assert_eq!(f.metadata().unwrap().len(), 6);
        // A symlink UNDER root pointing outside must not be followed.
        std::os::unix::fs::symlink(base.join("secret"), root.join("leak")).unwrap();
        assert!(rf.open_file_under(&["leak".to_string()]).is_err());
        // A symlinked intermediate dir must not be followed either.
        std::os::unix::fs::symlink(&base, root.join("up")).unwrap();
        assert!(rf
            .open_file_under(&["up".to_string(), "secret".to_string()])
            .is_err());

        // The docroot-swap attack: replace the docroot PATH with a symlink to a
        // sibling. The pinned fd still serves the ORIGINAL inode, not the swap.
        std::fs::write(base.join("evil.txt"), b"ATTACKER").unwrap();
        let evildir = base.join("evildir");
        std::fs::create_dir(&evildir).unwrap();
        std::fs::write(evildir.join("ok.txt"), b"SWAPPED!").unwrap();
        std::fs::remove_dir_all(&root).unwrap(); // remove original docroot path
        std::os::unix::fs::symlink(&evildir, &root).unwrap(); // path now → attacker dir
                                                              // A NEW open_ro of the (now-symlinked) path is refused…
        assert!(crate::dirs::SecureDir::open_ro(root.to_str().unwrap()).is_err());
        // …and the already-pinned fd still can't find ok.txt (original inode
        // was removed) — it never resolves the swapped path.
        assert!(rf.open_file_under(&["ok.txt".to_string()]).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn limiter_key_ip_aggregates_ipv6_by_64() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        // Two addresses in the same /64 collapse to one key.
        let a: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(limiter_key_ip(a), limiter_key_ip(b));
        assert_eq!(
            limiter_key_ip(a),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 0))
        );
        // A different /64 is a different key; IPv4 is unchanged.
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_ne!(limiter_key_ip(a), limiter_key_ip(c));
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(limiter_key_ip(v4), v4);
    }

    #[test]
    fn canonical_ip_unmaps_ipv4_mapped_but_not_native_v6() {
        use std::net::Ipv4Addr;
        // `::ffff:a.b.c.d` (the dual-stack peer form for an IPv4 client) becomes
        // the real IPv4 address, so it keys identically to a native-V4 peer.
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(
            canonical_ip(mapped),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
        let mapped2: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        assert_eq!(
            canonical_ip(mapped2),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))
        );
        // Native IPv6 (including loopback `::1`) is untouched — NOT turned into an
        // IPv4 address that could collide with a real client.
        let loop6: IpAddr = "::1".parse().unwrap();
        assert_eq!(canonical_ip(loop6), loop6);
        let native: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonical_ip(native), native);
    }

    #[test]
    fn conn_limiter_dual_stack_keys_do_not_collide() {
        // On a dual-stack `[::]` listener, distinct IPv4 peers arrive as mapped
        // IPv6 (`::ffff:a.b.c.d`). They must NOT share one budget with each other
        // or with native IPv6 (the bug: all mapped IPv4 collapsed to `::`).
        let v4a: IpAddr = "::ffff:198.51.100.1".parse().unwrap();
        let v4b: IpAddr = "::ffff:198.51.100.2".parse().unwrap();
        let native1: IpAddr = "2001:db8:a:b::1".parse().unwrap();
        let native2: IpAddr = "2001:db8:a:b:ffff::9".parse().unwrap(); // same /64 as native1
        let native_other: IpAddr = "2001:db8:a:c::1".parse().unwrap(); // different /64

        let lim = Arc::new(ConnLimiter::new(1));
        assert!(lim.admit_pending(v4a), "1st IPv4 peer admitted");
        assert!(
            lim.admit_pending(v4b),
            "a DIFFERENT IPv4 peer must have its own budget (not collapsed to ::)"
        );
        assert!(
            lim.admit_pending(native1),
            "native IPv6 independent of mapped IPv4"
        );
        assert!(
            !lim.admit_pending(native2),
            "native IPv6 in the same /64 shares one budget"
        );
        assert!(
            lim.admit_pending(native_other),
            "a different native /64 is independent"
        );
        // A mapped IPv4 and its native-V4 form are the SAME key.
        let lim2 = Arc::new(ConnLimiter::new(1));
        assert!(lim2.admit_pending("::ffff:10.0.0.5".parse().unwrap()));
        assert!(
            !lim2.admit_pending("10.0.0.5".parse().unwrap()),
            "mapped and native V4 share one budget"
        );
    }

    #[test]
    fn probe_handles_fragmented_status_line() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            // Backend flushes the status line in two fragments with a pause — a
            // single read() would see only "HTTP/1.1 2" and misjudge DOWN.
            tokio::spawn(async move {
                loop {
                    let (mut s, _) = listener.accept().await.unwrap();
                    let mut sink = [0u8; 512];
                    let _ = s.read(&mut sink).await;
                    s.write_all(b"HTTP/1.1 2").await.unwrap();
                    s.flush().await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    s.write_all(b"00 OK\r\nConnection: close\r\n\r\n")
                        .await
                        .unwrap();
                }
            });
            let hc = crate::config::HealthCheck {
                path: Some("/health".into()),
                interval: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
                healthy: 1,
                unhealthy: 1,
                expect_status: (200, 200),
            };
            assert!(
                probe(addr, &hc, false, "vhost.test").await,
                "fragmented 200 status line must count as UP"
            );
            let miss = crate::config::HealthCheck {
                expect_status: (204, 204),
                ..hc
            };
            assert!(
                !probe(addr, &miss, false, "vhost.test").await,
                "status outside the expected range must count as DOWN"
            );
        });
    }

    #[test]
    fn probe_incomplete_status_line_is_down() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            // Backend sends a plausible status WITHOUT a terminating CRLF and
            // then hangs — the exact "half response marked UP" round-6 finding.
            tokio::spawn(async move {
                loop {
                    let (mut s, _) = listener.accept().await.unwrap();
                    let mut sink = [0u8; 512];
                    let _ = s.read(&mut sink).await;
                    s.write_all(b"HTTP/1.1 200").await.unwrap();
                    s.flush().await.unwrap();
                    tokio::time::sleep(Duration::from_secs(30)).await; // hold open
                }
            });
            let hc = crate::config::HealthCheck {
                path: Some("/health".into()),
                interval: Duration::from_secs(1),
                timeout: Duration::from_millis(300),
                healthy: 1,
                unhealthy: 1,
                expect_status: (200, 200),
            };
            assert!(
                !probe(addr, &hc, false, "vhost.test").await,
                "a status line with no CRLF (hung backend) must be DOWN"
            );
        });
    }

    #[test]
    fn decode_query_catches_encoded_forms() {
        assert_eq!(decode_query("union%20select").0, "union select");
        assert_eq!(decode_query("union+select").0, "union select");
        assert_eq!(decode_query("union%09select").0, "union\tselect");
        assert_eq!(decode_query("plain=1").0, "plain=1");
        // Single decode stabilizes these.
        assert!(decode_query("plain=1").1);
        // Nested double/triple encoding is decoded until stable, then flagged stable.
        assert_eq!(decode_query("%252520").0, " ");
        assert!(decode_query("%252520").1);
    }

    #[test]
    fn path_decode_until_stable_catches_double_encoding() {
        // The WAF path bypass: `union%2520select` normalizes (single decode) to
        // `union%20select`, which a rule for "union select" misses — but the
        // decode-until-stable form recovers the literal payload. `+` is NOT a
        // space in a path (query-only), so it's preserved.
        let (d, stable) = decode_until_stable("/union%2520select", false);
        assert_eq!(d, "/union select");
        assert!(stable);
        assert_eq!(decode_until_stable("/a+b", false).0, "/a+b"); // path: + kept
        assert_eq!(decode_until_stable("a+b", true).0, "a b"); // query: + = space
                                                               // A very long input is treated as unstable (DoS guard) → caller fails
                                                               // closed rather than spin decoding.
        let huge = "%2520".repeat(4000); // > 16 KiB
        assert!(!decode_until_stable(&huge, false).1);
    }

    #[test]
    fn rewrite_stream_matches_pattern_split_across_chunks() {
        let f = [SubFilter {
            from: b"foobar".to_vec(),
            to: b"X".to_vec(),
        }];
        // "foobar" straddles the two chunks; max_from=6.
        let (e1, carry) = rewrite_stream(b"aa foo", &f, 6, false);
        let mut second = carry;
        second.extend_from_slice(b"bar bb");
        let (e2, _) = rewrite_stream(&second, &f, 6, true);
        let mut out = e1;
        out.extend_from_slice(&e2);
        assert_eq!(String::from_utf8_lossy(&out), "aa X bb");
    }

    #[test]
    fn rewrite_stream_no_match_passes_through() {
        let f = [SubFilter {
            from: b"zzz".to_vec(),
            to: b"Q".to_vec(),
        }];
        let (out, carry) = rewrite_stream(b"hello world", &f, 3, true);
        assert!(carry.is_empty());
        assert_eq!(&out, b"hello world");
    }

    /// Drive the streaming filter chunk-by-chunk (threading the carry-over) with a
    /// real end-of-stream on the LAST chunk — exactly what the non-cache response
    /// path does. This is the case the cache-fill path broke by never delivering
    /// EOS (round-8 finding 2): the trailing carry must always be flushed.
    fn run_stream(chunks: &[&[u8]], filters: &[SubFilter], max_from: usize) -> Vec<u8> {
        let mut carry: Vec<u8> = Vec::new();
        let mut out: Vec<u8> = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let last = i == chunks.len() - 1;
            let mut data = std::mem::take(&mut carry);
            data.extend_from_slice(chunk);
            let (emit, c) = rewrite_stream(&data, filters, max_from, last);
            out.extend_from_slice(&emit);
            carry = c;
        }
        assert!(carry.is_empty(), "carry must be flushed at end-of-stream");
        out
    }

    #[test]
    fn rewrite_stream_flushes_trailing_carry_on_eos() {
        // The reviewer's repro: a NO-MATCH tail must survive to the client. With a
        // 6-byte pattern the filter holds back up to 5 trailing bytes; without an
        // EOS flush an 8-byte body arrived as only 3 bytes. It must be complete.
        let f = [SubFilter {
            from: b"banana".to_vec(),
            to: b"X".to_vec(),
        }];
        assert_eq!(run_stream(&[b"FALLBACK"], &f, 6), b"FALLBACK");
        // Split across two chunks — same guarantee.
        assert_eq!(run_stream(&[b"FALL", b"BACK"], &f, 6), b"FALLBACK");

        // A body SHORTER than the longest pattern passes through intact.
        assert_eq!(run_stream(&[b"FAL"], &f, 6), b"FAL");
        assert_eq!(run_stream(&[b""], &f, 6), b"");

        // A match that completes EXACTLY at the last chunk boundary is applied
        // (not left dangling in the carry).
        let g = [SubFilter {
            from: b"END".to_vec(),
            to: b"XYZ".to_vec(),
        }];
        assert_eq!(run_stream(&[b"body-END"], &g, 3), b"body-XYZ");
        assert_eq!(run_stream(&[b"body-", b"EN", b"D"], &g, 3), b"body-XYZ");
        // A partial that looks like the start of a match but is the tail → emitted.
        assert_eq!(run_stream(&[b"body-EN"], &g, 3), b"body-EN");
    }

    fn upstream(host: &str, weight: u32) -> Upstream {
        Upstream {
            host: host.into(),
            port: 80,
            tls: false,
            sni: host.into(),
            host_header: None,
            verify: false,
            weight,
        }
    }

    #[test]
    fn ketama_distributes_roughly_evenly() {
        let ring = crate::config::build_ketama_ring(&[
            upstream("10.0.0.1", 1),
            upstream("10.0.0.2", 1),
            upstream("10.0.0.3", 1),
        ]);
        let mut counts = [0usize; 3];
        for i in 0..3000 {
            counts[ketama_pick(&ring, &format!("client-{i}"))] += 1;
        }
        // plain FNV gave e.g. 90/210/0; each should now be within ~±40% of 1000.
        for c in counts {
            assert!(
                c > 600 && c < 1400,
                "uneven ketama distribution: {counts:?}"
            );
        }
    }

    #[test]
    fn ketama_respects_weight() {
        let ring = crate::config::build_ketama_ring(&[upstream("a", 3), upstream("b", 1)]);
        let mut counts = [0usize; 2];
        for i in 0..4000 {
            counts[ketama_pick(&ring, &format!("client-{i}"))] += 1;
        }
        let ratio = counts[0] as f64 / counts[1] as f64;
        assert!(
            ratio > 2.2 && ratio < 4.0,
            "weight ~3:1 not honored: {counts:?}"
        );
    }
}

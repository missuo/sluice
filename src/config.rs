//! KDL config: parse `sluice.kdl` into a validated `Config`.
//!
//! Reads like nginx (brace blocks, directives), whitespace-insensitive. Syntax
//! errors carry `line:col` (from the `kdl` crate); semantic errors are keyed by
//! the offending block/host. `Config::parse` does syntax + semantic validation
//! (including rejecting unknown/mistyped directives inside blocks), and both
//! `sluice --check` and hot-reload go through it, so a bad edit never reaches a
//! running proxy.

use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

use ipnet::IpNet;
use kdl::{KdlDocument, KdlError, KdlNode};
use regex::Regex;

/// Cloudflare origin IP ranges (https://www.cloudflare.com/ips). Default set of
/// trusted proxies (for honoring the client-IP header) and the allow-list for
/// `access cloudflare-only`.
pub static CF_RANGES: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    const CIDRS: &[&str] = &[
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ];
    CIDRS.iter().filter_map(|s| s.parse().ok()).collect()
});

/// Render KDL syntax errors as `line:col: message` (kdl's own Display is terse).
fn fmt_kdl_error(e: KdlError) -> String {
    let src = e.input.as_str();
    let mut out = Vec::new();
    for d in &e.diagnostics {
        let (line, col) = line_col(src, d.span.offset());
        let msg = d.message.clone().unwrap_or_else(|| "syntax error".into());
        out.push(format!("{line}:{col}: {msg}"));
    }
    if out.is_empty() {
        "failed to parse KDL".to_string()
    } else {
        out.join("\n")
    }
}

fn line_col(src: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, ch) in src.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

pub struct Config {
    pub server: ServerCfg,
    pub client_ip_header: String,
    /// Only honor `client_ip_header` when the TCP peer is in this set (defaults
    /// to Cloudflare ranges). Prevents a direct client from spoofing their IP.
    pub trusted_proxies: Vec<IpNet>,
    pub geoip: Option<GeoipCfg>,
    pub listeners: Vec<Listener>,
    pub acme: Option<AcmeCfg>,
    /// Disk-backed response cache (None = the default in-memory LRU).
    pub disk_cache: Option<DiskCacheCfg>,
    pub unknown_host: u16,
    pub sites: Vec<Site>,
    /// host -> index into `sites`
    pub index: HashMap<String, usize>,
}

/// Access-log line format. `Text` (default) is the compact human-readable line;
/// `Json` emits one `serde_json` object per request for structured ingestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessLogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug)]
pub struct ServerCfg {
    pub threads: usize,
    pub metrics_addr: Option<String>,
    /// Format of the per-request access log line (`text` default, or `json`).
    pub access_log_format: AccessLogFormat,
    pub grace_period_secs: u64,
    pub graceful_shutdown_secs: u64,
    pub upstream_keepalive_pool: usize,
    pub upgrade_sock: Option<String>,
    /// Allow the process to keep running as UID 0. Off by default: sluice refuses
    /// to serve as root (a memory-safety bug in the TLS/proxy path would be a full
    /// host compromise) unless this is set or `SLUICE_ALLOW_ROOT=1` is exported.
    /// The supported deployment drops to a dedicated user via the systemd unit.
    pub allow_root: bool,
    /// Drop to this user/group after binding (Pingora privilege drop, used when
    /// daemonizing). The primary supported path is the systemd `User=`/`Group=`.
    pub run_user: Option<String>,
    pub run_group: Option<String>,
    /// Per-read downstream receive timeout (seconds). Tightens Pingora's inherited
    /// 60s per-read timeout so a slow/incomplete request body or a slow keepalive
    /// header read is cut sooner (Slowloris hardening).
    pub downstream_read_timeout_secs: u64,
    /// Absolute wall-clock deadline (seconds) for receiving the full request body
    /// once headers are complete. A body that drips past this is aborted, so a
    /// per-read timeout can't be reset forever by trickling one byte per interval.
    pub request_timeout_secs: u64,
    /// Per-write downstream response timeout (seconds). Bounds a slow-read (H1) or
    /// withheld-`WINDOW_UPDATE` (H2) client that stalls the response write and would
    /// otherwise pin a connection/FD/task with near-zero bandwidth. Applied to
    /// EVERY request on BOTH protocols, independent of `min_send_rate_bytes`. It is
    /// a PER-WRITE timeout (reset on each successful write), so a steadily-reading
    /// client is unaffected; only a fully stalled writer is cut. 0 = disabled
    /// (explicit opt-out; a config warning fires for an unprotected listener).
    pub downstream_write_timeout_secs: u64,
    /// Minimum downstream send rate (bytes/sec) for the response. 0 = off. The
    /// stricter, adaptive H1 policy (a no-op on H2); when set it takes priority over
    /// the flat `downstream_write_timeout_secs` on H1. Guards against a slow-read
    /// client holding a connection while draining the response one byte at a time.
    pub min_send_rate_bytes: usize,
    /// Maximum concurrent downstream connections per client IP. 0 = off. Enforced
    /// at TCP accept (before the TLS handshake), so a single source cannot tie up
    /// the whole connection/file-descriptor budget with held-open connections.
    /// NOTE: leave 0 when fronted by Cloudflare (all peers share CF edge IPs).
    pub max_conn_per_ip: u32,
    /// Absolute timeout (seconds) for the downstream TLS handshake, replacing
    /// Pingora's former hardcoded 60s. A partial ClientHello otherwise retains a
    /// socket/task for the whole window before any Sluice code runs (pre-HTTP
    /// Slowloris on direct exposure). Also used as the per-IP connection limiter's
    /// pending-slot TTL so pre-handshake accounting tracks the same window. Minimum
    /// 1s. Default 10s.
    pub tls_handshake_timeout_secs: u64,
    /// Idle-connection timeout (seconds) for a downstream HTTP/2 connection that
    /// has NO active streams. Stock Pingora waits for the next stream forever, so
    /// a client that completes the H2 handshake and then opens no stream (or goes
    /// idle between streams) pins the socket/TLS/H2 state/FD for the connection's
    /// whole life — one silent source could exhaust the FD budget. A long-running
    /// ACTIVE stream keeps the connection open; only a fully idle connection is
    /// closed once this elapses. 0 = disabled (unbounded, stock behavior). Mirrors
    /// the built-in 60s H1 keepalive idle default.
    pub h2_idle_timeout_secs: u64,
    /// Absolute timeout (seconds) for the downstream HTTP/2 connection-preface
    /// handshake. Stock Pingora awaits the 24-byte client preface with NO deadline,
    /// and `h2-idle-timeout-secs` only starts AFTER the handshake — so a client that
    /// negotiates ALPN `h2` over TLS and then sends no (or a dripped partial) preface
    /// pins the socket/TLS/H2 allocations/conn-limit guard/task indefinitely (one
    /// direct source could exhaust the FD budget). This bounds the preface wait; it
    /// stays FINITE even when the idle timeout is disabled. A prompt valid preface is
    /// unaffected. Minimum 1s. Default 10s.
    pub h2_handshake_timeout_secs: u64,
    /// Total deadline (seconds) for resolving a hostname upstream to an address.
    /// Upstream DNS is done asynchronously off the request path; a resolver
    /// outage/NXDOMAIN/empty answer returns a bounded 502 (never a panic or an
    /// unbounded blocking lookup that pins worker threads). IP-literal backends skip
    /// DNS entirely. Minimum 1s. Default 5s.
    pub upstream_dns_timeout_secs: u64,
    /// Fresh TTL (seconds) for a cached upstream DNS answer: within this window the
    /// resolver is NOT consulted (no `getaddrinfo` per request). On expiry the
    /// last-known-good answer is served immediately while a single background
    /// refresh runs (serve-stale-while-revalidate). Minimum 1s. Default 30s.
    pub upstream_dns_ttl_secs: u64,
    /// How long (seconds) a last-known-good DNS answer keeps being served AFTER its
    /// TTL when the resolver is failing/slow, so healthy upstream pools survive a
    /// transient DNS outage. 0 = never serve stale (fail with a 502 the moment the
    /// TTL lapses and re-resolution fails). Default 300s.
    pub upstream_dns_stale_secs: u64,
    /// Global cap on concurrent (blocking) upstream DNS resolutions. Bounds how many
    /// `getaddrinfo` calls run at once so a DNS flood/outage can't spawn unbounded
    /// blocking work; combined with per-name singleflight coalescing. Minimum 1.
    /// Default 8.
    pub upstream_dns_max_concurrent: u32,
}

impl Default for ServerCfg {
    fn default() -> Self {
        ServerCfg {
            threads: 0, // 0 = all cores (resolved in main)
            metrics_addr: None,
            access_log_format: AccessLogFormat::Text,
            grace_period_secs: 30,
            graceful_shutdown_secs: 300,
            upstream_keepalive_pool: 256,
            upgrade_sock: None,
            allow_root: false,
            run_user: None,
            run_group: None,
            downstream_read_timeout_secs: 15,
            request_timeout_secs: 30,
            downstream_write_timeout_secs: 60,
            min_send_rate_bytes: 0,
            max_conn_per_ip: 0,
            tls_handshake_timeout_secs: 10,
            h2_idle_timeout_secs: 60,
            h2_handshake_timeout_secs: 10,
            upstream_dns_timeout_secs: 5,
            upstream_dns_ttl_secs: 30,
            upstream_dns_stale_secs: 300,
            upstream_dns_max_concurrent: 8,
        }
    }
}

pub struct GeoipCfg {
    pub country_header: Option<String>,
    pub log_fields: Vec<String>,
    pub metric_labels: Vec<String>,
    /// Opened MaxMind readers (re-opened on each reload). None = feature off.
    pub asn_reader: Option<maxminddb::Reader<Vec<u8>>>,
    pub city_reader: Option<maxminddb::Reader<Vec<u8>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub addr: String,
    pub kind: ListenerKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerKind {
    Tls {
        cert: String,
        key: String,
        http2: bool,
    },
    /// SNI-based certs loaded from a directory (`<host>.crt`/`<host>.key`),
    /// served via Pingora's TLS callback and hot-swappable.
    TlsDynamic {
        cert_dir: String,
        http2: bool,
    },
    /// Certs auto-provisioned via ACME (needs a top-level `acme {}` block).
    TlsAcme {
        http2: bool,
    },
    RedirectHttps,
}

/// Disk-backed response cache. When set, cached responses persist to `dir`
/// (survive restarts, hold far more than memory) instead of the in-memory LRU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskCacheCfg {
    pub dir: String,
    /// Soft cap on total on-disk size; a reaper evicts the oldest entries.
    pub max_size: u64,
    /// Cap on the number of cache files (guards against inode exhaustion).
    pub max_files: u64,
    /// Keep at least this many free bytes on the filesystem; evict below it.
    pub min_free: u64,
}

/// Automatic TLS via ACME (Let's Encrypt). Provisions a cert per `site` host
/// over HTTP-01 — requires each domain to resolve to this server with :80 open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeCfg {
    pub contact: String,
    pub staging: bool,
    pub cache_dir: String,
}

/// A proxy backend. `https://host[:port]` → TLS with SNI + Host rewrite;
/// bare `host:port` → plaintext, client Host preserved (local-backend semantics).
#[derive(Debug, Clone)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub sni: String,
    /// Host header to send upstream. None = preserve the client's Host.
    pub host_header: Option<String>,
    pub verify: bool,
    /// Relative share of traffic (default 1). Used by round-robin, random, and
    /// the size of this backend's arc on the Ketama ring.
    pub weight: u32,
}

/// Load-balancing policy across a pool of backends.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Balance {
    RoundRobin,
    Random,
    /// Sticky by client IP via plain modulo (simple; remaps everything when the
    /// pool size changes — use `Ketama` if that matters).
    IpHash,
    /// Sticky by client IP via a consistent-hash ring: adding/removing a backend
    /// only remaps ~1/n of clients, and `weight` scales each backend's share.
    Ketama,
    /// Fewest in-flight requests wins (weighted): sends each request to the least
    /// busy backend — best when request durations vary a lot.
    LeastConn,
}

/// One or more backends selected by a `Balance` policy, with connect-failure
/// failover to the next server in the pool.
#[derive(Debug, Clone)]
pub struct UpstreamGroup {
    pub servers: Vec<Upstream>,
    pub balance: Balance,
    /// Active background health checking for this pool (None = passive only).
    pub health_check: Option<HealthCheck>,
    /// Precomputed Ketama hash ring `(point_hash → server index)`, sorted by
    /// hash. Empty unless `balance` is `Ketama`. Built once at config load.
    pub ring: Vec<(u64, usize)>,
}

/// Active health check (like Caddy's `health_checks active`): a background task
/// probes each backend on an interval; a backend is taken out of rotation after
/// `unhealthy` consecutive failures and returned after `healthy` successes.
#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// HTTP GET path to probe (plaintext backends). None = TCP-connect check.
    pub path: Option<String>,
    pub interval: Duration,
    pub timeout: Duration,
    pub healthy: u32,
    pub unhealthy: u32,
    /// Inclusive expected HTTP status range for an HTTP check.
    pub expect_status: (u16, u16),
}

/// How a `location` matches the request path.
#[derive(Debug, Clone)]
pub enum Matcher {
    /// `location "/api/"` — path starts with this.
    Prefix(String),
    /// `location "~\.php$"` — path matches this regex.
    Regex(Regex),
}

impl Matcher {
    pub fn matches(&self, path: &str) -> bool {
        match self {
            // Segment-aware prefix: "/api" matches "/api" and "/api/…" but NOT
            // "/api-internal", so a broad location can't silently shadow a
            // restricted sibling. A prefix ending in "/" matches at that boundary.
            Matcher::Prefix(p) => {
                if !path.starts_with(p.as_str()) {
                    return false;
                }
                path.len() == p.len()
                    || p.ends_with('/')
                    || path.as_bytes().get(p.len()) == Some(&b'/')
            }
            Matcher::Regex(re) => re.is_match(path),
        }
    }
}

/// What a matched location does with the request.
pub enum Handler {
    Proxy(UpstreamGroup),
    File {
        /// The docroot pinned by fd at config load (`SecureDir::open_ro`, which
        /// refuses symlink components). Requests serve via `openat` from THIS
        /// fd, so a low-priv user swapping the docroot path afterwards can't
        /// re-route reads to another directory (a per-request re-open would).
        root_fd: std::sync::Arc<crate::dirs::SecureDir>,
        /// Kept for the access log and the cache-epoch fingerprint.
        root: String,
        index: String,
        /// Bounded hot-file cache scoped to THIS docroot (`root_fd`). Built once
        /// at config load, so a reload creates a new root + a fresh cache and can
        /// never serve stale content from an old root.
        cache: std::sync::Arc<crate::staticfiles::StaticFileCache>,
    },
}

/// A path-routed block inside a `site`. Locations are matched in declaration
/// order; the first whose matcher matches wins (put specific paths before `/`).
pub struct Location {
    pub matcher: Matcher,
    pub handler: Handler,
    pub websocket: bool,
    pub max_body: Option<u64>,
    pub read_timeout: Option<Duration>,
    /// Paths matching any of these regexes get 403 (nginx `deny`).
    pub deny: Vec<Regex>,
    /// Response caching for this location (None = pass-through).
    pub cache: Option<CacheCfg>,
    /// Streaming response-body find/replace (nginx `sub_filter`).
    pub sub_filters: Vec<SubFilter>,
    /// Longest `from` across `sub_filters` (carry-over size for chunk matching).
    pub sub_max_from: usize,
}

/// One response-body find/replace rule (bytes, so it works on any text encoding).
#[derive(Debug, Clone)]
pub struct SubFilter {
    pub from: Vec<u8>,
    pub to: Vec<u8>,
}

/// Response-cache settings for a location.
#[derive(Debug, Clone)]
pub struct CacheCfg {
    /// Fallback TTL when the upstream sends no explicit freshness.
    pub ttl: Duration,
    /// Max object size to cache (bytes); larger responses stream uncached.
    pub max_object: usize,
}

/// A WAF rule: if the chosen request field matches `re`, the request is blocked.
#[derive(Debug)]
pub struct WafRule {
    pub field: WafField,
    pub re: Regex,
    pub status: u16,
}

#[derive(Debug)]
pub enum WafField {
    Path,
    Query,
    Method,
    /// A named request header (lowercased), e.g. `user-agent`.
    Header(String),
}

pub struct Site {
    pub host: String,
    /// Path-routed handlers, matched in order. Always non-empty after parsing.
    pub locations: Vec<Location>,
    /// Site-wide deny (checked before location routing).
    pub deny: Vec<Regex>,
    /// Site-wide WAF rules (checked first of all).
    pub waf: Vec<WafRule>,
    pub hsts: Option<String>,
    pub cloudflare_only: bool,
    pub rate_limit: Option<RateLimit>,
    pub redirects: Vec<Redirect>,
    /// Provision an ACME cert for this host (opt-in; needs an `acme {}` block and
    /// a `tls acme=true` listener). Off by default so CF-fronted hosts, which
    /// can't pass HTTP-01, don't trigger endless failed validations.
    pub acme: bool,
    /// Fingerprint of this site's content-affecting config (matchers, upstream
    /// servers + Host rewrites, file roots, sub-filters). It namespaces the
    /// response-cache key, so a reload/restart/upgrade that points the site at
    /// a different upstream cannot keep serving the OLD config's cached
    /// responses. Identical config → identical epoch → the persistent disk
    /// cache still survives restarts.
    pub cache_epoch: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimit {
    pub rps: f64,
    pub burst: f64,
}

#[derive(Debug)]
pub struct Redirect {
    pub re: Regex,
    pub target: String,
    pub status: u16,
}

// ---- small KDL accessors ----

fn first_arg(node: &KdlNode) -> Option<&str> {
    node.entries()
        .iter()
        .find(|e| e.name().is_none())
        .and_then(|e| e.value().as_string())
}
fn first_arg_int(node: &KdlNode) -> Option<i128> {
    node.entries()
        .iter()
        .find(|e| e.name().is_none())
        .and_then(|e| e.value().as_integer())
}
fn first_arg_bool(node: &KdlNode) -> Option<bool> {
    node.entries()
        .iter()
        .find(|e| e.name().is_none())
        .and_then(|e| e.value().as_bool())
}
fn all_args(node: &KdlNode) -> Vec<String> {
    node.entries()
        .iter()
        .filter(|e| e.name().is_none())
        .filter_map(|e| e.value().as_string().map(str::to_owned))
        .collect()
}
fn prop_str<'a>(node: &'a KdlNode, key: &str) -> Option<&'a str> {
    node.get(key).and_then(|v| v.as_string())
}
fn prop_int(node: &KdlNode, key: &str) -> Option<i128> {
    node.get(key).and_then(|v| v.as_integer())
}
fn prop_bool(node: &KdlNode, key: &str) -> Option<bool> {
    node.get(key).and_then(|v| v.as_bool())
}
fn child<'a>(node: &'a KdlNode, name: &str) -> Option<&'a KdlNode> {
    node.children()?
        .nodes()
        .iter()
        .find(|n| n.name().value() == name)
}
fn child_arg<'a>(node: &'a KdlNode, name: &str) -> Option<&'a str> {
    first_arg(child(node, name)?)
}
fn child_int(node: &KdlNode, name: &str) -> Option<i128> {
    first_arg_int(child(node, name)?)
}
fn child_bool(node: &KdlNode, name: &str) -> Option<bool> {
    first_arg_bool(child(node, name)?)
}
/// A numeric property that accepts both integers and floats (e.g. `rps=0.5`).
fn prop_f64(node: &KdlNode, key: &str) -> Option<f64> {
    let v = node.get(key)?;
    v.as_float().or_else(|| v.as_integer().map(|i| i as f64))
}

#[derive(Clone, Copy)]
enum Ty {
    Int,
    /// Integer or float (e.g. `rps`).
    Num,
    Bool,
    Str,
}
impl Ty {
    fn describe(self) -> &'static str {
        match self {
            Ty::Int => "an integer",
            Ty::Num => "a number",
            Ty::Bool => "true or false",
            Ty::Str => "a quoted string",
        }
    }
    fn matches(self, v: &kdl::KdlValue) -> bool {
        match self {
            Ty::Int => v.as_integer().is_some(),
            // Reject non-finite floats (`1.0e999` parses to +inf): they'd silently
            // become an unbounded rate limit / burst.
            Ty::Num => {
                v.as_integer().is_some() || v.as_float().map(f64::is_finite).unwrap_or(false)
            }
            Ty::Bool => v.as_bool().is_some(),
            Ty::Str => v.as_string().is_some(),
        }
    }
}

/// Count a node's positional (unnamed) entries — its arguments, not its `k=v`
/// properties.
fn positional_count(node: &KdlNode) -> usize {
    node.entries().iter().filter(|e| e.name().is_none()).count()
}

/// RFC 7230 `token` byte (valid in a header field name).
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// `32MiB` / `1024` / `512KB` -> bytes.
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix("GiB") {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("MiB") {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("KiB") {
        (n, 1024)
    } else if let Some(n) = s.strip_suffix("GB") {
        (n, 1_000_000_000)
    } else if let Some(n) = s.strip_suffix("MB") {
        (n, 1_000_000)
    } else if let Some(n) = s.strip_suffix("KB") {
        (n, 1000)
    } else if let Some(n) = s.strip_suffix('B') {
        (n, 1)
    } else {
        (s, 1)
    };
    let v: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid size {s:?}"))?;
    v.checked_mul(mult)
        .ok_or_else(|| format!("size {s:?} overflows u64"))
}

fn open_mmdb(
    path: &str,
    label: &str,
    errs: &mut Vec<String>,
) -> Option<maxminddb::Reader<Vec<u8>>> {
    if !Path::new(path).exists() {
        errs.push(format!("geoip {label} not found: {path}"));
        return None;
    }
    match maxminddb::Reader::open_readfile(path) {
        Ok(r) => Some(r),
        Err(e) => {
            errs.push(format!("geoip {label} {path}: {e}"));
            None
        }
    }
}

/// Parse an upstream: `https://host[:port]` (TLS+SNI, Host rewritten to host),
/// `http://host[:port]`, or bare `host:port` (plaintext, client Host preserved).
fn parse_upstream(s: &str) -> Result<Upstream, String> {
    let (tls, rest, default_port, url_form) = if let Some(r) = s.strip_prefix("https://") {
        (true, r, 443u16, true)
    } else if let Some(r) = s.strip_prefix("http://") {
        (false, r, 80u16, true)
    } else {
        (false, s, 0u16, false)
    };
    // An upstream is an ORIGIN (host[:port]), not a URL. Reject a query/fragment
    // outright (`https://h?x`, `https://h#y`) — for BOTH forms, since the bare
    // form's suffix was previously unchecked and silently dropped.
    if rest.contains('?') || rest.contains('#') {
        return Err(format!(
            "upstream {s:?}: query/fragment not allowed — give just host[:port]"
        ));
    }
    let hostport = rest.split('/').next().unwrap_or(rest);
    // No path/trailing-slash. A URL form may end in a bare `/` (`https://h/`);
    // the bare `host:port` form may NOT (`127.0.0.1:9/` used to silently drop it).
    let after_authority = &rest[hostport.len()..];
    let allowed_suffix = if url_form {
        after_authority == "/"
    } else {
        false
    };
    if !after_authority.is_empty() && !allowed_suffix {
        return Err(format!(
            "upstream {s:?}: a path/trailing-slash is not allowed — give just host[:port]"
        ));
    }
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:8080`. Host keeps no brackets.
        let (addr, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("upstream {s:?}: unclosed IPv6 bracket"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| format!("upstream {s:?}: bad port {p:?}"))?,
            None if after.is_empty() && default_port != 0 => default_port,
            None if after.is_empty() => {
                return Err(format!("upstream {s:?}: IPv6 literal needs a :port"))
            }
            None => {
                return Err(format!(
                    "upstream {s:?}: junk after IPv6 address: {after:?}"
                ))
            }
        };
        (addr.to_string(), port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| format!("upstream {s:?}: bad port {p:?}"))?,
            ),
            None if default_port != 0 => (hostport.to_string(), default_port),
            None => {
                return Err(format!(
                    "upstream {s:?} must be host:port or a http(s):// URL"
                ))
            }
        }
    };
    if host.is_empty() {
        return Err(format!("upstream {s:?}: empty host"));
    }
    if port == 0 {
        return Err(format!("upstream {s:?}: port 0 is not valid"));
    }
    // Strict authority. An IPv6 literal (already bracket-stripped) may contain
    // `:` and hex; a hostname/IPv4 is alphanumeric + `.-_`. Reject anything else
    // (whitespace, control, `@` userinfo, `%`-encoding like `api%2etest`), and a
    // hostname label that starts or ends with `-` (`-bad.test`).
    let is_v6 = host.contains(':');
    let charset_ok = host.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || (is_v6 && b == b':')
    });
    let labels_ok = is_v6
        || host
            .split('.')
            .all(|l| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-'));
    if !charset_ok || !labels_ok {
        return Err(format!("upstream {s:?}: invalid host {host:?}"));
    }
    // RFC 1035 length limits: a DNS name is at most 253 bytes and each label at
    // most 63. An over-long label/name can NEVER resolve, and previously slipped
    // past `--check` only to reach the request-path resolver. Reject it here.
    if !is_v6 {
        if host.len() > 253 {
            return Err(format!(
                "upstream {s:?}: host is {} bytes, over the 253-byte DNS name limit",
                host.len()
            ));
        }
        if let Some(l) = host.split('.').find(|l| l.len() > 63) {
            return Err(format!(
                "upstream {s:?}: DNS label {l:?} is {} bytes, over the 63-byte limit",
                l.len()
            ));
        }
    }
    // Host header authority for a URL-form upstream (`http(s)://…`): the origin
    // sees THIS as `Host`, so it must be a syntactically valid authority — an IPv6
    // literal stays BRACKETED (`[::1]`, not `::1`), and a non-default port is kept
    // (RFC 9110 §7.2 omits the scheme's default port, e.g. `:443` for https). The
    // bare `host:port` form has `host_header = None` and preserves the client's
    // Host downstream. `host`/`sni` remain the bracketless host for DNS/dial/SNI.
    let host_header = if url_form {
        let bracketed = if is_v6 {
            format!("[{host}]")
        } else {
            host.clone()
        };
        let authority = if port == default_port {
            bracketed
        } else {
            format!("{bracketed}:{port}")
        };
        // Validate the constructed authority (defense in depth; also catches an
        // exotic host the charset check let through but a Host parser rejects).
        authority.parse::<http::uri::Authority>().map_err(|_| {
            format!("upstream {s:?}: computed Host authority {authority:?} is invalid")
        })?;
        Some(authority)
    } else {
        None
    };
    Ok(Upstream {
        sni: host.clone(),
        host_header,
        tls,
        verify: tls,
        host,
        port,
        weight: 1,
    })
}

/// Stable, well-distributed hash for Ketama ring points and key lookup. FNV-1a
/// per-byte fold (deterministic across Rust versions, unlike `DefaultHasher`)
/// followed by a splitmix64 finalizer for avalanche — plain FNV clusters badly
/// on the shared-prefix `host:port-<n>` ring-point strings, which skewed the
/// distribution. Must match `proxy::str_hash`.
pub fn stable_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // splitmix64 finalizer
    h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 31)
}

/// Build a Ketama consistent-hash ring: each backend gets `160 * weight` points,
/// so its share of the key space is proportional to its weight and removing one
/// backend only reshuffles that backend's arcs.
pub fn build_ketama_ring(servers: &[Upstream]) -> Vec<(u64, usize)> {
    let mut ring = Vec::new();
    for (idx, s) in servers.iter().enumerate() {
        let points = 160usize.saturating_mul(s.weight.max(1) as usize);
        for p in 0..points {
            ring.push((stable_hash(&format!("{}:{}-{p}", s.host, s.port)), idx));
        }
    }
    ring.sort_by_key(|(h, _)| *h);
    ring
}

// ---- declarative config schema ----
//
// Every node is validated against a `Spec`: how many positional arguments it
// takes (and their type), which `key=value` properties it accepts (and their
// types), which children its block may contain (and how often), and whether it
// may carry a block at all. The walk is fully recursive, so an unknown
// directive, stray property, duplicate property or singleton, extra argument,
// wrong type, or unexpected block is an error at EVERY level — `--check`
// accepts exactly the shapes the server consumes, nothing more. Adding a
// directive means adding it here AND consuming it in the parse functions.

#[derive(Clone, Copy, PartialEq)]
enum Rep {
    Once,
    Many,
}

struct Spec {
    /// Inclusive (min, max) positional-argument count.
    args: (usize, usize),
    /// Type every positional argument must have.
    arg_ty: Ty,
    /// For `Ty::Int` arguments: the inclusive value range. Catches negatives
    /// that were silently clamped and huge values that silently narrowed
    /// (`healthy 4294967296` used to truncate to 0 via `as u32`).
    int_range: Option<(i128, i128)>,
    /// Allowed `key=value` properties and their types.
    props: &'static [(&'static str, Ty)],
    /// `None` = leaf (having a `{ }` block is an error); `Some` = the allowed
    /// children with their multiplicity.
    children: Option<&'static [(&'static str, Rep, &'static Spec)]>,
    /// Structural rule that doesn't fit the table (e.g. upstream's two forms).
    extra: Option<fn(&KdlNode, &str, &mut Vec<String>)>,
}

const fn leaf(min: usize, max: usize, ty: Ty) -> Spec {
    Spec {
        args: (min, max),
        arg_ty: ty,
        int_range: None,
        props: &[],
        children: None,
        extra: None,
    }
}

/// An integer leaf whose single argument must lie in `lo..=hi`.
const fn int_leaf(lo: i128, hi: i128) -> Spec {
    Spec {
        args: (1, 1),
        arg_ty: Ty::Int,
        int_range: Some((lo, hi)),
        props: &[],
        children: None,
        extra: None,
    }
}

static STR1: Spec = leaf(1, 1, Ty::Str);
static BOOL1: Spec = leaf(1, 1, Ty::Bool);
/// One or more string arguments (list leaves like `trusted-proxies`).
static STRS: Spec = leaf(1, usize::MAX, Ty::Str);

// Integer leaves with semantic ranges (negatives were silently clamped and
// oversized values silently narrowed before — now they're config errors).
static SECS0: Spec = int_leaf(0, 31_536_000); // durations that may be 0 (ttl, grace)
static SECS1: Spec = int_leaf(1, 86_400); // durations that must be >= 1s
static STREAK: Spec = int_leaf(1, 100_000); // health up/down thresholds
static HTTP_STATUS: Spec = int_leaf(100, 599);
static THREADS: Spec = int_leaf(0, 4096);
static POOL0: Spec = int_leaf(0, 1_000_000); // upstream-keepalive-pool
static RATE0: Spec = int_leaf(0, 1_000_000_000); // min-send-rate-bytes (0 = off)
static CONC1: Spec = int_leaf(1, 4096); // concurrency limit, must be >= 1
static FILES1: Spec = int_leaf(1, 1_000_000_000_000); // cache-store max-files

static SERVER_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("threads", Rep::Once, &THREADS),
        ("metrics-addr", Rep::Once, &STR1),
        ("access-log-format", Rep::Once, &STR1),
        ("grace-period-secs", Rep::Once, &SECS0),
        ("graceful-shutdown-secs", Rep::Once, &SECS0),
        ("upstream-keepalive-pool", Rep::Once, &POOL0),
        ("upgrade-sock", Rep::Once, &STR1),
        ("allow-root", Rep::Once, &BOOL1),
        ("user", Rep::Once, &STR1),
        ("group", Rep::Once, &STR1),
        ("downstream-read-timeout-secs", Rep::Once, &SECS1),
        ("request-timeout-secs", Rep::Once, &SECS1),
        ("downstream-write-timeout-secs", Rep::Once, &SECS0),
        ("min-send-rate-bytes", Rep::Once, &RATE0),
        ("max-conn-per-ip", Rep::Once, &POOL0),
        ("tls-handshake-timeout-secs", Rep::Once, &SECS1),
        ("h2-idle-timeout-secs", Rep::Once, &SECS0),
        ("h2-handshake-timeout-secs", Rep::Once, &SECS1),
        ("upstream-dns-timeout-secs", Rep::Once, &SECS1),
        ("upstream-dns-ttl-secs", Rep::Once, &SECS1),
        ("upstream-dns-stale-secs", Rep::Once, &SECS0),
        ("upstream-dns-max-concurrent", Rep::Once, &CONC1),
    ]),
    extra: None,
};

static CLIENT_IP_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("trusted-header", Rep::Once, &STR1),
        ("trusted-proxies", Rep::Once, &STRS),
    ]),
    extra: None,
};

static GEOIP_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("enabled", Rep::Once, &BOOL1),
        ("country-header", Rep::Once, &STR1),
        ("mmdb-asn", Rep::Once, &STR1),
        ("mmdb-city", Rep::Once, &STR1),
        ("log-fields", Rep::Once, &STRS),
        ("metric-labels", Rep::Once, &STRS),
    ]),
    extra: None,
};

static ACME_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("enabled", Rep::Once, &BOOL1),
        ("contact", Rep::Once, &STR1),
        ("staging", Rep::Once, &BOOL1),
        ("cache-dir", Rep::Once, &STR1),
    ]),
    extra: None,
};

static CACHE_STORE_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("dir", Rep::Once, &STR1),
        ("max-size", Rep::Once, &STR1),
        ("max-files", Rep::Once, &FILES1),
        ("min-free", Rep::Once, &STR1),
    ]),
    extra: None,
};

static DEFAULTS_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("hsts", Rep::Once, &STR1),
        ("unknown-host", Rep::Once, &HTTP_STATUS),
    ]),
    extra: None,
};

static TLS_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[
        ("cert", Ty::Str),
        ("key", Ty::Str),
        ("cert-dir", Ty::Str),
        ("acme", Ty::Bool),
    ],
    children: None,
    extra: None,
};

static LISTENER_SPEC: Spec = Spec {
    args: (1, 1),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("http2", Rep::Once, &BOOL1),
        ("redirect-to-https", Rep::Once, &BOOL1),
        ("tls", Rep::Once, &TLS_SPEC),
    ]),
    extra: None,
};

static UPSTREAM_SERVER_SPEC: Spec = Spec {
    args: (1, 1),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[("weight", Ty::Int)],
    children: None,
    extra: None,
};

static HEALTH_CHECK_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("path", Rep::Once, &STR1),
        ("interval-secs", Rep::Once, &SECS1),
        ("timeout-secs", Rep::Once, &SECS1),
        ("healthy", Rep::Once, &STREAK),
        ("unhealthy", Rep::Once, &STREAK),
        ("expect-status", Rep::Once, &HTTP_STATUS),
    ]),
    extra: None,
};

static UPSTREAM_SPEC: Spec = Spec {
    args: (0, 1),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("server", Rep::Many, &UPSTREAM_SERVER_SPEC),
        ("balance", Rep::Once, &STR1),
        ("health-check", Rep::Once, &HEALTH_CHECK_SPEC),
    ]),
    extra: Some(upstream_one_form),
};

/// `upstream` has two forms — the `upstream "host:port"` shorthand or a block
/// with `server` lines. Mixing them (a positional arg AND a block) silently
/// merged both before; require exactly one form.
fn upstream_one_form(node: &KdlNode, ctx: &str, errs: &mut Vec<String>) {
    let has_arg = positional_count(node) > 0;
    let has_block = node.children().is_some_and(|c| !c.nodes().is_empty());
    if has_arg && has_block {
        errs.push(format!(
            "{ctx}: use either the `upstream \"host:port\"` shorthand or a block \
             with `server` lines, not both"
        ));
    }
}

static FILE_SERVER_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("root", Rep::Once, &STR1),
        ("index", Rep::Once, &STR1),
        ("cache-ttl-secs", Rep::Once, &SECS0),
    ]),
    extra: None,
};

static CACHE_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("ttl-secs", Rep::Once, &SECS0),
        ("max-object", Rep::Once, &STR1),
    ]),
    extra: None,
};

static RATE_LIMIT_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[("rps", Ty::Num), ("burst", Ty::Num)],
    children: None,
    extra: None,
};

static ACCESS_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[("cloudflare-only", Ty::Bool)],
    children: None,
    extra: None,
};

static REDIRECT_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[("match", Ty::Str), ("target", Ty::Str), ("status", Ty::Int)],
    children: None,
    extra: None,
};

static SUB_FILTER_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[("from", Ty::Str), ("to", Ty::Str)],
    children: None,
    extra: None,
};

static WAF_BLOCK_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[("field", Ty::Str), ("match", Ty::Str), ("status", Ty::Int)],
    children: None,
    extra: None,
};

static WAF_SPEC: Spec = Spec {
    args: (0, 0),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[("block", Rep::Many, &WAF_BLOCK_SPEC)]),
    extra: None,
};

static DENY_SPEC: Spec = leaf(1, 1, Ty::Str);

static LOCATION_SPEC: Spec = Spec {
    args: (1, 1),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("upstream", Rep::Once, &UPSTREAM_SPEC),
        ("file-server", Rep::Once, &FILE_SERVER_SPEC),
        ("websocket", Rep::Once, &BOOL1),
        ("max-body", Rep::Once, &STR1),
        ("read-timeout-secs", Rep::Once, &SECS1),
        ("deny", Rep::Many, &DENY_SPEC),
        ("cache", Rep::Once, &CACHE_SPEC),
        ("sub-filter", Rep::Many, &SUB_FILTER_SPEC),
        ("upstream-host", Rep::Once, &STR1),
        ("upstream-verify", Rep::Once, &BOOL1),
    ]),
    extra: None,
};

static SITE_SPEC: Spec = Spec {
    args: (1, 1),
    arg_ty: Ty::Str,
    int_range: None,
    props: &[],
    children: Some(&[
        ("location", Rep::Many, &LOCATION_SPEC),
        ("upstream", Rep::Once, &UPSTREAM_SPEC),
        ("file-server", Rep::Once, &FILE_SERVER_SPEC),
        ("deny", Rep::Many, &DENY_SPEC),
        ("redirect", Rep::Many, &REDIRECT_SPEC),
        ("rate-limit", Rep::Once, &RATE_LIMIT_SPEC),
        ("access", Rep::Once, &ACCESS_SPEC),
        ("waf", Rep::Once, &WAF_SPEC),
        ("hsts", Rep::Once, &STR1),
        ("acme", Rep::Once, &BOOL1),
        ("websocket", Rep::Once, &BOOL1),
        ("max-body", Rep::Once, &STR1),
        ("read-timeout-secs", Rep::Once, &SECS1),
        ("upstream-host", Rep::Once, &STR1),
        ("upstream-verify", Rep::Once, &BOOL1),
        ("sub-filter", Rep::Many, &SUB_FILTER_SPEC),
        ("cache", Rep::Once, &CACHE_SPEC),
    ]),
    extra: None,
};

static ROOT_CHILDREN: &[(&str, Rep, &Spec)] = &[
    ("server", Rep::Once, &SERVER_SPEC),
    ("client-ip", Rep::Once, &CLIENT_IP_SPEC),
    ("geoip", Rep::Once, &GEOIP_SPEC),
    ("acme", Rep::Once, &ACME_SPEC),
    ("cache-store", Rep::Once, &CACHE_STORE_SPEC),
    ("defaults", Rep::Once, &DEFAULTS_SPEC),
    ("listener", Rep::Many, &LISTENER_SPEC),
    ("site", Rep::Many, &SITE_SPEC),
];

/// Label a node for error messages: a `site` carries its host so several sites'
/// errors stay distinguishable; everything else is `parent name`.
fn node_label(parent: &str, name: &str, node: &KdlNode) -> String {
    let own = if name == "site" {
        format!("site `{}`", first_arg(node).unwrap_or("?"))
    } else {
        name.to_string()
    };
    if parent.is_empty() {
        own
    } else {
        format!("{parent} {own}")
    }
}

/// Validate one node against its spec (args, props, block, children), recursing
/// into children. `ctx` is this node's own label.
fn walk(node: &KdlNode, spec: &Spec, ctx: &str, errs: &mut Vec<String>) {
    // Positional arguments: count and type.
    let n = positional_count(node);
    let (min, max) = spec.args;
    if n < min || n > max {
        let want = if min == max {
            format!("exactly {min}")
        } else if max == usize::MAX {
            format!("at least {min}")
        } else {
            format!("{min} to {max}")
        };
        errs.push(format!("{ctx}: expected {want} argument(s), found {n}"));
    }
    if max > 0 {
        for e in node.entries().iter().filter(|e| e.name().is_none()) {
            if !spec.arg_ty.matches(e.value()) {
                errs.push(format!(
                    "{ctx}: argument must be {}",
                    spec.arg_ty.describe()
                ));
            } else if let (Some((lo, hi)), Some(v)) = (spec.int_range, e.value().as_integer()) {
                if v < lo || v > hi {
                    errs.push(format!("{ctx}: value {v} out of range ({lo}..={hi})"));
                }
            }
        }
    }
    // Properties: unknown, wrong type, duplicated.
    let mut seen_props: Vec<&str> = Vec::new();
    for e in node.entries() {
        let Some(k) = e.name() else { continue };
        let kname = k.value();
        match spec.props.iter().find(|(p, _)| *p == kname) {
            None => errs.push(format!("{ctx}: unknown property `{kname}`")),
            Some((_, ty)) if !ty.matches(e.value()) => {
                errs.push(format!(
                    "{ctx}: property `{kname}` must be {}",
                    ty.describe()
                ));
            }
            Some(_) => {}
        }
        if seen_props.contains(&kname) {
            errs.push(format!("{ctx}: duplicate property `{kname}`"));
        } else {
            seen_props.push(kname);
        }
    }
    // Block and children.
    match spec.children {
        None => {
            if node.children().is_some() {
                errs.push(format!("{ctx}: takes no block"));
            }
        }
        Some(allowed) => {
            if let Some(ch) = node.children() {
                let mut seen: Vec<&str> = Vec::new();
                for c in ch.nodes() {
                    let cname = c.name().value();
                    let Some((_, rep, cspec)) = allowed.iter().find(|(a, _, _)| *a == cname) else {
                        errs.push(format!("{ctx}: unknown directive `{cname}`"));
                        continue;
                    };
                    if *rep == Rep::Once && seen.contains(&cname) {
                        errs.push(format!("{ctx}: `{cname}` given more than once"));
                    }
                    seen.push(cname);
                    let cctx = node_label(ctx, cname, c);
                    walk(c, cspec, &cctx, errs);
                }
            }
        }
    }
    if let Some(f) = spec.extra {
        f(node, ctx, errs);
    }
}

/// Validate the whole document against the schema. Unknown TOP-LEVEL directives
/// are reported by the parse loop (which skips them), so they aren't duplicated
/// here; everything else — including a duplicate top-level singleton block — is.
fn validate_schema(doc: &KdlDocument, errs: &mut Vec<String>) {
    let mut seen: Vec<&str> = Vec::new();
    for node in doc.nodes() {
        let name = node.name().value();
        let Some((_, rep, spec)) = ROOT_CHILDREN.iter().find(|(a, _, _)| *a == name) else {
            continue; // reported as "unknown top-level directive" by the parser
        };
        if *rep == Rep::Once && seen.contains(&name) {
            errs.push(format!("duplicate `{name}` block (only one allowed)"));
        }
        seen.push(name);
        let ctx = node_label("", name, node);
        walk(node, spec, &ctx, errs);
    }
}

const TOP_LEVEL: &[&str] = &[
    "server",
    "client-ip",
    "geoip",
    "acme",
    "cache-store",
    "listener",
    "defaults",
    "site",
];

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        Config::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        // Phase 1: syntax. Use KDL v1 grammar so bare `true`/`false` work (v2
        // requires `#true`); this matches River's config ergonomics and reads
        // more like nginx.
        let doc = KdlDocument::parse_v1(text).map_err(fmt_kdl_error)?;

        // Phase 2: build + semantic validation, accumulating errors.
        let mut errs: Vec<String> = Vec::new();
        let mut server = ServerCfg::default();
        let mut client_ip_header = "cf-connecting-ip".to_string();
        let mut trusted_proxies: Vec<IpNet> = Vec::new();
        let mut trusted_proxies_set = false;
        let mut geoip = None;
        let mut listeners = Vec::new();
        let mut acme: Option<AcmeCfg> = None;
        let mut disk_cache: Option<DiskCacheCfg> = None;
        let mut default_hsts = None;
        let mut unknown_host = 404u16;
        let mut sites: Vec<Site> = Vec::new();

        for node in doc.nodes() {
            let name = node.name().value();
            if !TOP_LEVEL.contains(&name) {
                errs.push(format!("unknown top-level directive `{name}`"));
                continue;
            }
            match name {
                "server" => {
                    if let Some(v) = child_int(node, "threads") {
                        if !(0..=4096).contains(&v) {
                            errs.push(format!("server threads: {v} out of range (0..=4096)"));
                        }
                        server.threads = v.clamp(0, 4096) as usize;
                    }
                    if let Some(v) = child_arg(node, "metrics-addr") {
                        server.metrics_addr = Some(v.to_string());
                    }
                    if let Some(v) = child_arg(node, "access-log-format") {
                        match v {
                            "text" => server.access_log_format = AccessLogFormat::Text,
                            "json" => server.access_log_format = AccessLogFormat::Json,
                            other => errs.push(format!(
                                "server access-log-format: unknown value {other:?} (text|json)"
                            )),
                        }
                    }
                    if let Some(v) = child_int(node, "grace-period-secs") {
                        server.grace_period_secs = v.max(0) as u64;
                    }
                    if let Some(v) = child_int(node, "graceful-shutdown-secs") {
                        server.graceful_shutdown_secs = v.max(0) as u64;
                    }
                    if let Some(v) = child_int(node, "upstream-keepalive-pool") {
                        server.upstream_keepalive_pool = v.max(0) as usize;
                    }
                    if let Some(v) = child_arg(node, "upgrade-sock") {
                        server.upgrade_sock = Some(v.to_string());
                    }
                    if let Some(v) = child_bool(node, "allow-root") {
                        server.allow_root = v;
                    }
                    if let Some(v) = child_arg(node, "user") {
                        server.run_user = Some(v.to_string());
                    }
                    if let Some(v) = child_arg(node, "group") {
                        server.run_group = Some(v.to_string());
                    }
                    if let Some(v) = child_int(node, "downstream-read-timeout-secs") {
                        server.downstream_read_timeout_secs = v.max(1) as u64;
                    }
                    if let Some(v) = child_int(node, "request-timeout-secs") {
                        server.request_timeout_secs = v.max(1) as u64;
                    }
                    if let Some(v) = child_int(node, "downstream-write-timeout-secs") {
                        server.downstream_write_timeout_secs = v.max(0) as u64;
                    }
                    if let Some(v) = child_int(node, "min-send-rate-bytes") {
                        server.min_send_rate_bytes = v.max(0) as usize;
                    }
                    if let Some(v) = child_int(node, "max-conn-per-ip") {
                        server.max_conn_per_ip = v.max(0) as u32;
                    }
                    if let Some(v) = child_int(node, "tls-handshake-timeout-secs") {
                        server.tls_handshake_timeout_secs = v.max(1) as u64;
                    }
                    if let Some(v) = child_int(node, "h2-idle-timeout-secs") {
                        server.h2_idle_timeout_secs = v.max(0) as u64;
                    }
                    if let Some(v) = child_int(node, "h2-handshake-timeout-secs") {
                        server.h2_handshake_timeout_secs = v.max(1) as u64;
                    }
                    if let Some(v) = child_int(node, "upstream-dns-timeout-secs") {
                        server.upstream_dns_timeout_secs = v.max(1) as u64;
                    }
                    if let Some(v) = child_int(node, "upstream-dns-ttl-secs") {
                        server.upstream_dns_ttl_secs = v.max(1) as u64;
                    }
                    if let Some(v) = child_int(node, "upstream-dns-stale-secs") {
                        server.upstream_dns_stale_secs = v.max(0) as u64;
                    }
                    if let Some(v) = child_int(node, "upstream-dns-max-concurrent") {
                        server.upstream_dns_max_concurrent = v.max(1) as u32;
                    }
                }
                "client-ip" => {
                    if let Some(v) = child_arg(node, "trusted-header") {
                        client_ip_header = v.to_ascii_lowercase();
                    }
                    if let Some(tp) = child(node, "trusted-proxies") {
                        trusted_proxies_set = true;
                        for a in all_args(tp) {
                            match a.parse::<IpNet>() {
                                Ok(net) => trusted_proxies.push(net),
                                Err(_) => {
                                    errs.push(format!("client-ip trusted-proxies: bad CIDR {a:?}"))
                                }
                            }
                        }
                    }
                }
                "geoip" => {
                    let enabled = child_bool(node, "enabled").unwrap_or(true);
                    if enabled {
                        let country_header =
                            child_arg(node, "country-header").map(|s| s.to_ascii_lowercase());
                        let log_fields =
                            child(node, "log-fields").map(all_args).unwrap_or_default();
                        // Reject an unknown log-field NOW (a typo like `counrty`
                        // was silently dropped at request time and produced an
                        // empty column forever).
                        for f in &log_fields {
                            if !matches!(f.as_str(), "country" | "asn" | "asn-org" | "city") {
                                errs.push(format!(
                                    "geoip log-fields: unknown field `{f}` (country|asn|asn-org|city)"
                                ));
                            }
                        }
                        let metric_labels = child(node, "metric-labels")
                            .map(all_args)
                            .unwrap_or_default();
                        for l in &metric_labels {
                            if l != "country" {
                                errs.push(format!(
                                    "geoip metric-labels: `{l}` is high-cardinality; only `country` is allowed as a metric label"
                                ));
                            }
                        }
                        let asn_reader = child_arg(node, "mmdb-asn")
                            .and_then(|p| open_mmdb(p, "mmdb-asn", &mut errs));
                        let city_reader = child_arg(node, "mmdb-city")
                            .and_then(|p| open_mmdb(p, "mmdb-city", &mut errs));
                        geoip = Some(GeoipCfg {
                            country_header,
                            log_fields,
                            metric_labels,
                            asn_reader,
                            city_reader,
                        });
                    }
                }
                "listener" => match parse_listener(node) {
                    Ok(l) => listeners.push(l),
                    Err(e) => errs.push(e),
                },
                "acme" => {
                    let enabled = child_bool(node, "enabled").unwrap_or(true);
                    if enabled {
                        match child_arg(node, "contact") {
                            Some(c) => {
                                let dir = child_arg(node, "cache-dir")
                                    .unwrap_or("/var/lib/sluice/acme")
                                    .to_string();
                                // READ-ONLY validation here (parse runs for
                                // `--check`, which must not touch the FS): if the
                                // dir already exists it must be a non-symlink dir
                                // owned by us. Startup does the create + 0700 +
                                // fd-pinning via dirs::SecureDir. Run `--check` as
                                // the service user for it to be meaningful.
                                if let Err(e) = crate::dirs::validate(&dir) {
                                    errs.push(format!("acme cache-dir: {e}"));
                                }
                                acme = Some(AcmeCfg {
                                    contact: c.to_string(),
                                    staging: child_bool(node, "staging").unwrap_or(false),
                                    cache_dir: dir,
                                });
                            }
                            None => errs.push("acme: `contact` (an email) is required".to_string()),
                        }
                    }
                }
                "cache-store" => match child_arg(node, "dir") {
                    Some(dir) => {
                        let size =
                            |name: &str, default: u64, errs: &mut Vec<String>| match child_arg(
                                node, name,
                            ) {
                                Some(s) => parse_size(s).unwrap_or_else(|e| {
                                    errs.push(format!("cache-store {name}: {e}"));
                                    default
                                }),
                                None => default,
                            };
                        let max_size = size("max-size", 10 * 1024 * 1024 * 1024, &mut errs);
                        let min_free = size("min-free", 1024 * 1024 * 1024, &mut errs);
                        let max_files = child_int(node, "max-files")
                            .map(|v| v.max(1) as u64)
                            .unwrap_or(1_000_000);
                        // READ-ONLY validation (see the acme note above): startup
                        // creates + locks + fd-pins the dir via dirs::SecureDir,
                        // and every cache write is done relative to that fd, so a
                        // local user can't reroute a shard via a swapped symlink.
                        if let Err(e) = crate::dirs::validate(dir) {
                            errs.push(format!("cache-store dir: {e}"));
                        }
                        disk_cache = Some(DiskCacheCfg {
                            dir: dir.to_string(),
                            max_size,
                            max_files,
                            min_free,
                        });
                    }
                    None => errs.push("cache-store: `dir` is required".to_string()),
                },
                "defaults" => {
                    if let Some(v) = child_arg(node, "hsts") {
                        if v.chars().any(|c| c.is_control()) {
                            errs.push(
                                "defaults hsts: must not contain control characters".to_string(),
                            );
                        }
                        default_hsts = Some(v.to_string());
                    }
                    if let Some(v) = child_int(node, "unknown-host") {
                        match u16::try_from(v) {
                            Ok(c) if (100..=599).contains(&c) => unknown_host = c,
                            _ => errs.push(format!(
                                "defaults unknown-host: {v} is not a valid HTTP status"
                            )),
                        }
                    }
                }
                "site" => match parse_site(node) {
                    Ok(s) => sites.push(s),
                    Err(e) => errs.push(e),
                },
                _ => unreachable!(),
            }
        }

        // Validate the whole document against the declarative schema (typos,
        // stray props/args, duplicates, wrong types → errors, not silent no-ops).
        validate_schema(&doc, &mut errs);

        // apply default hsts to sites that didn't set their own
        for s in &mut sites {
            if s.hsts.is_none() {
                s.hsts = default_hsts.clone();
            }
        }

        // build host index; catch duplicates
        let mut index = HashMap::new();
        for (i, s) in sites.iter().enumerate() {
            if index.insert(s.host.clone(), i).is_some() {
                errs.push(format!("duplicate site host `{}`", s.host));
            }
        }

        if listeners.is_empty() {
            errs.push("no `listener` defined".to_string());
        }
        // Two acceptors on one address both try to bind → the second fails at
        // startup, after --check said ok. Compare PARSED addresses so `:19550`
        // and `:019550` (same socket, different string) are caught too — AND
        // treat a wildcard (unspecified `0.0.0.0`/`[::]`) as conflicting with ANY
        // same-port address, IGNORING family: `0.0.0.0:80` binds `127.0.0.1:80`,
        // and `[::]:80` binds IPv4 too on a default dual-stack Linux, so a plain
        // or same-family check let those pairs through. Conservatively flagging a
        // wildcard-vs-anything overlap is safer than a startup bind fight.
        use std::net::SocketAddr;
        let paddr = |s: &str| s.parse::<SocketAddr>().ok();
        let conflict = |a: &SocketAddr, b: &SocketAddr| -> bool {
            a.port() == b.port()
                && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
        };
        for (i, l) in listeners.iter().enumerate() {
            if let Some(a) = paddr(&l.addr) {
                if listeners[..i]
                    .iter()
                    .filter_map(|p| paddr(&p.addr))
                    .any(|b| conflict(&a, &b))
                {
                    errs.push(format!("conflicting listener address `{}`", l.addr));
                }
            }
        }
        // metrics-addr is bound at startup; validate it, and reject a collision
        // with a listener (Pingora would then randomly share the port between the
        // metrics service and the proxy — breaking both).
        if let Some(m) = &server.metrics_addr {
            match paddr(m) {
                None => errs.push(format!(
                    "server metrics-addr {m:?}: not a valid socket address"
                )),
                Some(ma)
                    if listeners
                        .iter()
                        .filter_map(|l| paddr(&l.addr))
                        .any(|l| conflict(&ma, &l)) =>
                {
                    errs.push(format!(
                        "server metrics-addr {m:?} collides with a listener address"
                    ));
                }
                Some(_) => {}
            }
        }
        let has_acme_listener = listeners
            .iter()
            .any(|l| matches!(l.kind, ListenerKind::TlsAcme { .. }));
        if acme.is_none() && has_acme_listener {
            errs.push(
                "a listener uses `tls acme=true` but there is no `acme {}` block".to_string(),
            );
        }
        // HTTP-01 challenges are answered on the :80 redirect listener; without a
        // redirect listener *on port 80* ACME can never validate.
        if has_acme_listener
            && !listeners.iter().any(|l| {
                matches!(l.kind, ListenerKind::RedirectHttps)
                    && paddr(&l.addr).map(|a| a.port() == 80).unwrap_or(false)
            })
        {
            errs.push(
                "`tls acme=true` needs a `listener \"0.0.0.0:80\" { redirect-to-https true }` \
                 (on port 80) to answer HTTP-01 challenges"
                    .to_string(),
            );
        }
        // ACME is opt-in per site (`acme true`). Tie the flag to the machinery.
        let any_acme_site = sites.iter().any(|s| s.acme);
        if any_acme_site && acme.is_none() {
            errs.push("a site sets `acme true` but there is no `acme {}` block".to_string());
        }
        if any_acme_site && !has_acme_listener {
            errs.push("a site sets `acme true` but no listener uses `tls acme=true`".to_string());
        }
        if sites.is_empty() {
            errs.push("no `site` defined".to_string());
        }

        if trusted_proxies.is_empty() {
            if trusted_proxies_set {
                // The user configured trusted-proxies but none parsed — don't
                // silently fall back to trusting Cloudflare (wrong peers).
                errs.push("client-ip trusted-proxies: no valid CIDR was given".to_string());
            } else {
                trusted_proxies = CF_RANGES.clone();
            }
        }

        // Downstream write-DoS boundary. A directly-exposed (TLS) listener with the
        // per-write timeout disabled AND no adaptive send-rate floor AND no per-IP
        // connection cap has NO application-level bound on a slow-read / withheld-
        // `WINDOW_UPDATE` client that pins connections/FDs with near-zero bandwidth.
        // Warn (rather than fail) since a fronting edge (e.g. Cloudflare) may supply
        // the boundary; the default `downstream-write-timeout-secs=60` avoids it.
        let has_serving_listener = listeners
            .iter()
            .any(|l| !matches!(l.kind, ListenerKind::RedirectHttps));
        if has_serving_listener
            && server.downstream_write_timeout_secs == 0
            && server.min_send_rate_bytes == 0
            && server.max_conn_per_ip == 0
        {
            log::warn!(
                "a TLS listener is exposed with downstream-write-timeout-secs=0, \
                 min-send-rate-bytes=0, and max-conn-per-ip=0: a slow-read / \
                 withheld-WINDOW_UPDATE client can pin connections with no bound. \
                 Set downstream-write-timeout-secs (default 60) unless a fronting \
                 edge (e.g. Cloudflare) already provides that boundary."
            );
        }

        if errs.is_empty() {
            Ok(Config {
                server,
                client_ip_header,
                trusted_proxies,
                geoip,
                listeners,
                acme,
                disk_cache,
                unknown_host,
                sites,
                index,
            })
        } else {
            Err(errs.join("\n"))
        }
    }
}

fn parse_listener(node: &KdlNode) -> Result<Listener, String> {
    let addr = first_arg(node)
        .ok_or("listener needs an address, e.g. listener \"0.0.0.0:443\"")?
        .to_string();
    // validate addr parses
    addr.parse::<std::net::SocketAddr>()
        .map_err(|_| format!("listener {addr:?}: not a valid socket address"))?;

    if child_bool(node, "redirect-to-https").unwrap_or(false) {
        if child(node, "tls").is_some() {
            return Err(format!(
                "listener {addr:?}: `redirect-to-https` and a `tls` block are mutually exclusive"
            ));
        }
        return Ok(Listener {
            addr,
            kind: ListenerKind::RedirectHttps,
        });
    }
    let tls = child(node, "tls").ok_or_else(|| {
        format!("listener {addr:?}: needs a `tls` block or `redirect-to-https true`")
    })?;
    let http2 = child_bool(node, "http2").unwrap_or(false);

    // ACME-managed certs (needs a top-level `acme {}` block).
    if prop_bool(tls, "acme").unwrap_or(false) {
        if prop_str(tls, "cert").is_some()
            || prop_str(tls, "key").is_some()
            || prop_str(tls, "cert-dir").is_some()
        {
            return Err(format!(
                "listener {addr:?}: `tls acme=true` can't be combined with cert/key/cert-dir"
            ));
        }
        return Ok(Listener {
            addr,
            kind: ListenerKind::TlsAcme { http2 },
        });
    }
    // Dynamic SNI certs from a directory, or a single cert/key pair.
    if let Some(dir) = prop_str(tls, "cert-dir") {
        if !Path::new(dir).is_dir() {
            return Err(format!(
                "listener {addr:?}: cert-dir not a directory: {dir}"
            ));
        }
        // Actually load the store at --check time so an empty directory or one
        // with only malformed pairs is caught now, not when the server boots and
        // immediately exits. (`--check` must reject anything startup would.)
        if let Err(e) = crate::certs::CertStore::from_dir_strict(dir) {
            return Err(format!("listener {addr:?}: cert-dir: {e}"));
        }
        return Ok(Listener {
            addr,
            kind: ListenerKind::TlsDynamic {
                cert_dir: dir.to_string(),
                http2,
            },
        });
    }
    let cert = prop_str(tls, "cert")
        .ok_or_else(|| format!("listener {addr:?}: tls needs cert+key or cert-dir"))?
        .to_string();
    let key = prop_str(tls, "key")
        .ok_or_else(|| format!("listener {addr:?}: tls missing key"))?
        .to_string();
    if !Path::new(&cert).exists() {
        return Err(format!("listener {addr:?}: cert file not found: {cert}"));
    }
    if !Path::new(&key).exists() {
        return Err(format!("listener {addr:?}: key file not found: {key}"));
    }
    // Actually load the pair at --check time so a malformed PEM or a key that
    // doesn't match the cert is caught now, not at the first TLS handshake.
    if let Err(e) = crate::certs::Cert::from_files(&cert, &key) {
        return Err(format!("listener {addr:?}: tls cert/key: {e}"));
    }
    Ok(Listener {
        addr,
        kind: ListenerKind::Tls { cert, key, http2 },
    })
}

/// Collect `deny "<regex>"` children into compiled regexes.
fn parse_deny(node: &KdlNode, host: &str) -> Result<Vec<Regex>, String> {
    let mut deny = Vec::new();
    if let Some(children) = node.children() {
        for d in children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "deny")
        {
            let pat =
                first_arg(d).ok_or_else(|| format!("site `{host}`: deny needs a path regex"))?;
            deny.push(
                Regex::new(pat).map_err(|e| format!("site `{host}`: deny regex {pat:?}: {e}"))?,
            );
        }
    }
    Ok(deny)
}

fn parse_max_body(node: &KdlNode, host: &str) -> Result<Option<u64>, String> {
    match child_arg(node, "max-body") {
        Some(s) => Ok(Some(
            parse_size(s).map_err(|e| format!("site `{host}`: {e}"))?,
        )),
        None => Ok(None),
    }
}

fn parse_cache(node: &KdlNode, host: &str) -> Result<Option<CacheCfg>, String> {
    match child(node, "cache") {
        Some(c) => {
            let ttl = child_int(c, "ttl-secs").unwrap_or(60).max(0) as u64;
            let max_object = match child_arg(c, "max-object") {
                Some(s) => parse_size(s).map_err(|e| format!("site `{host}`: cache {e}"))? as usize,
                None => 8 * 1024 * 1024,
            };
            Ok(Some(CacheCfg {
                ttl: Duration::from_secs(ttl),
                max_object,
            }))
        }
        None => Ok(None),
    }
}

/// Parse an `upstream` node — either `upstream "host:port"` (single) or a block
/// with several `server "..."` lines and an optional `balance` policy.
fn parse_upstream_group(node: &KdlNode, host: &str) -> Result<UpstreamGroup, String> {
    let mut servers = Vec::new();
    if let Some(single) = first_arg(node) {
        servers.push(parse_upstream(single).map_err(|e| format!("site `{host}`: {e}"))?);
    }
    let mut balance = Balance::RoundRobin;
    if let Some(children) = node.children() {
        for s in children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "server")
        {
            let a = first_arg(s)
                .ok_or_else(|| format!("site `{host}`: upstream server needs an address"))?;
            let mut u = parse_upstream(a).map_err(|e| format!("site `{host}`: {e}"))?;
            if let Some(w) = prop_int(s, "weight") {
                // Bounded (not up to u32::MAX): a huge weight with `balance ketama`
                // would build a multi-GB hash ring and OOM at load/reload. 1000:1
                // is already an extreme ratio.
                if !(1..=1000).contains(&w) {
                    return Err(format!(
                        "site `{host}`: server {a:?} weight must be 1..=1000"
                    ));
                }
                u.weight = w as u32;
            }
            servers.push(u);
        }
        if let Some(b) = child_arg(node, "balance") {
            balance = match b {
                "round-robin" => Balance::RoundRobin,
                "random" => Balance::Random,
                "ip-hash" => Balance::IpHash,
                "ketama" => Balance::Ketama,
                "least-conn" => Balance::LeastConn,
                other => {
                    return Err(format!(
                        "site `{host}`: unknown balance {other:?} \
                         (round-robin|random|ip-hash|ketama|least-conn)"
                    ))
                }
            };
        }
    }
    if servers.is_empty() {
        return Err(format!("site `{host}`: upstream has no servers"));
    }
    let health_check = match child(node, "health-check") {
        Some(h) => Some(parse_health_check(h, host)?),
        None => None,
    };
    let ring = if balance == Balance::Ketama {
        build_ketama_ring(&servers)
    } else {
        Vec::new()
    };
    Ok(UpstreamGroup {
        servers,
        balance,
        health_check,
        ring,
    })
}

fn parse_health_check(node: &KdlNode, host: &str) -> Result<HealthCheck, String> {
    let path = child_arg(node, "path").map(str::to_owned);
    if let Some(p) = &path {
        reject_ctl("health-check path", p, host)?;
        if !p.starts_with('/') || p.contains(' ') {
            return Err(format!(
                "site `{host}`: health-check path must start with '/' and contain no spaces"
            ));
        }
    }
    let interval = Duration::from_secs(child_int(node, "interval-secs").unwrap_or(5).max(1) as u64);
    let timeout = Duration::from_secs(child_int(node, "timeout-secs").unwrap_or(2).max(1) as u64);
    let healthy = child_int(node, "healthy").unwrap_or(2).max(1) as u32;
    let unhealthy = child_int(node, "unhealthy").unwrap_or(3).max(1) as u32;
    let expect_status = match child_int(node, "expect-status") {
        Some(v) => {
            let s = u16::try_from(v)
                .ok()
                .filter(|s| (100..=599).contains(s))
                .ok_or_else(|| format!("site `{host}`: health-check expect-status {v} invalid"))?;
            (s, s)
        }
        None => (200, 399),
    };
    Ok(HealthCheck {
        path,
        interval,
        timeout,
        healthy,
        unhealthy,
        expect_status,
    })
}

/// The backend of a site or location: exactly one of `upstream` / `file-server`.
fn parse_handler(node: &KdlNode, host: &str) -> Result<Handler, String> {
    match (child(node, "upstream"), child(node, "file-server")) {
        (Some(_), Some(_)) => Err(format!(
            "site `{host}`: set either upstream or file-server, not both"
        )),
        (Some(u), None) => {
            let mut group = parse_upstream_group(u, host)?;
            if let Some(h) = child_arg(node, "upstream-host") {
                reject_ctl("upstream-host", h, host)?;
                // It goes straight into the upstream Host header, so it must be a
                // syntactically valid host[:port] — no spaces or other bytes that
                // an origin/CDN would reject or that could split the header.
                let host_ok = !h.is_empty()
                    && h.len() <= 253
                    && h.bytes().all(|b| {
                        b.is_ascii_alphanumeric()
                            || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
                    });
                if !host_ok {
                    return Err(format!(
                        "site `{host}`: upstream-host {h:?} is not a valid host[:port]"
                    ));
                }
                for s in &mut group.servers {
                    s.host_header = Some(h.to_string());
                }
            }
            if let Some(v) = child_bool(node, "upstream-verify") {
                for s in &mut group.servers {
                    s.verify = v;
                }
            }
            Ok(Handler::Proxy(group))
        }
        (None, Some(f)) => {
            let root = child_arg(f, "root")
                .ok_or_else(|| format!("site `{host}`: file-server missing root"))?
                .to_string();
            // Pin the docroot by fd NOW, refusing symlink components — instead of
            // `Path::is_dir` (which follows symlinks) + a per-request path re-open
            // (which a swapped docroot could re-route to a root-only dir). The fd
            // is held in the config snapshot and every request `openat`s from it.
            let root_fd = std::sync::Arc::new(
                crate::dirs::SecureDir::open_ro(&root)
                    .map_err(|e| format!("site `{host}`: file-server root not usable: {e}"))?,
            );
            let index = child_arg(f, "index").unwrap_or("index.html").to_string();
            // The index is appended as a path component when a directory is
            // requested, so it MUST be a single, plain basename — `index
            // "../Cargo.toml"` (or an absolute path) would otherwise escape the
            // docroot. (open_regular_under also rejects bad components at
            // request time; this is the first line of defense, at config load.)
            if index.is_empty()
                || index == "."
                || index == ".."
                || index.contains('/')
                || index.contains('\\')
                || index.contains('\0')
            {
                return Err(format!(
                    "site `{host}`: file-server index must be a plain filename, not {index:?}"
                ));
            }
            // Hot-file cache TTL: how long a cached small-file snapshot is served
            // before a fresh secure re-open re-validates it. Default 1s; `0`
            // disables the content cache (the fused single-hop read still applies).
            let cache_ttl = child_int(f, "cache-ttl-secs")
                .map(|v| v.max(0) as u64)
                .unwrap_or(1);
            let cache =
                crate::staticfiles::StaticFileCache::new(std::time::Duration::from_secs(cache_ttl));
            Ok(Handler::File {
                root_fd,
                root,
                index,
                cache,
            })
        }
        (None, None) => Err(format!("site `{host}`: needs an upstream or a file-server")),
    }
}

fn parse_read_timeout(node: &KdlNode) -> Option<Duration> {
    child_int(node, "read-timeout-secs").map(|v| Duration::from_secs(v.max(0) as u64))
}

/// Parse `sub-filter from="..." to="..."` children (response-body rewrites).
fn parse_sub_filters(node: &KdlNode, host: &str) -> Result<(Vec<SubFilter>, usize), String> {
    let mut fs = Vec::new();
    if let Some(children) = node.children() {
        for f in children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "sub-filter")
        {
            let from = prop_str(f, "from")
                .ok_or_else(|| format!("site `{host}`: sub-filter needs from=\"...\""))?;
            if from.is_empty() {
                return Err(format!("site `{host}`: sub-filter from must be non-empty"));
            }
            let to = prop_str(f, "to").unwrap_or("");
            fs.push(SubFilter {
                from: from.as_bytes().to_vec(),
                to: to.as_bytes().to_vec(),
            });
        }
    }
    let max = fs.iter().map(|f| f.from.len()).max().unwrap_or(0);
    Ok((fs, max))
}

/// A `location "<matcher>" { ... }` block. `~` prefix on the matcher = regex,
/// otherwise a path prefix.
fn parse_location(node: &KdlNode, host: &str) -> Result<Location, String> {
    let m =
        first_arg(node).ok_or_else(|| format!("site `{host}`: location needs a path matcher"))?;
    let matcher = if let Some(rx) = m.strip_prefix('~') {
        Matcher::Regex(
            Regex::new(rx.trim())
                .map_err(|e| format!("site `{host}`: location regex {:?}: {e}", rx.trim()))?,
        )
    } else {
        Matcher::Prefix(m.to_string())
    };
    let (sub_filters, sub_max_from) = parse_sub_filters(node, host)?;
    Ok(Location {
        matcher,
        handler: parse_handler(node, host)?,
        websocket: child_bool(node, "websocket").unwrap_or(false),
        max_body: parse_max_body(node, host)?,
        read_timeout: parse_read_timeout(node),
        deny: parse_deny(node, host)?,
        cache: parse_cache(node, host)?,
        sub_filters,
        sub_max_from,
    })
}

/// A `waf { block field=".." match=".." }` block (site-wide request filtering).
fn parse_waf(node: &KdlNode, host: &str) -> Result<Vec<WafRule>, String> {
    let mut rules = Vec::new();
    let Some(w) = child(node, "waf") else {
        return Ok(rules);
    };
    let Some(children) = w.children() else {
        return Ok(rules);
    };
    for b in children
        .nodes()
        .iter()
        .filter(|n| n.name().value() == "block")
    {
        let field_s = prop_str(b, "field")
            .ok_or_else(|| format!("site `{host}`: waf block needs field=\"...\""))?;
        let field = if let Some(h) = field_s.strip_prefix("header:") {
            // The name must be a valid HTTP header token (RFC 7230), else the
            // rule can never match a real header and is silently dead. `header:`
            // (empty) and `header:bad name` (space) are both rejected here.
            if h.is_empty() || !h.bytes().all(is_token_byte) {
                return Err(format!(
                    "site `{host}`: waf field={field_s:?} — invalid header name (e.g. header:x-api-key)"
                ));
            }
            WafField::Header(h.to_ascii_lowercase())
        } else {
            match field_s {
                "path" => WafField::Path,
                "query" => WafField::Query,
                "method" => WafField::Method,
                "user-agent" => WafField::Header("user-agent".to_string()),
                other => {
                    return Err(format!(
                        "site `{host}`: waf unknown field {other:?} (path|query|method|user-agent|header:NAME)"
                    ))
                }
            }
        };
        let pat = prop_str(b, "match")
            .ok_or_else(|| format!("site `{host}`: waf block needs match=\"...\""))?;
        let re = Regex::new(pat).map_err(|e| format!("site `{host}`: waf regex {pat:?}: {e}"))?;
        let raw = prop_int(b, "status").unwrap_or(403);
        let status = u16::try_from(raw)
            .ok()
            .filter(|s| (400..=599).contains(s))
            .ok_or_else(|| format!("site `{host}`: waf status {raw} not in 400..=599"))?;
        rules.push(WafRule { field, re, status });
    }
    Ok(rules)
}

/// Reject values that get embedded into HTTP header lines (HSTS, Host, probe
/// request line, Location) if they carry control bytes — header injection from
/// a config file is still header injection.
fn reject_ctl(what: &str, v: &str, host: &str) -> Result<(), String> {
    if v.chars().any(|c| c.is_control()) {
        return Err(format!(
            "site `{host}`: {what} must not contain control characters"
        ));
    }
    Ok(())
}

fn parse_site(node: &KdlNode) -> Result<Site, String> {
    let raw_host = first_arg(node)
        .ok_or("site needs a host, e.g. site \"app.example.com\"")?
        .to_string();
    // Requests arrive with the Host lowercased, so normalize here — an
    // uppercase site would never match (and two case-variant sites would dodge
    // duplicate detection). Validate the charset so a host can't smuggle
    // whitespace/CRLF into the :80 redirect Location or the index key.
    let host = raw_host.to_ascii_lowercase();
    if host.is_empty() {
        return Err("site: host must not be empty".to_string());
    }
    if host.len() > 253
        || !host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_'))
    {
        return Err(format!("site {raw_host:?}: not a valid hostname"));
    }

    // Locations: explicit `location` blocks first (matched in order), then any
    // site-level bare `upstream`/`file-server` as an implicit catch-all "/".
    let mut locations = Vec::new();
    if let Some(children) = node.children() {
        for l in children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "location")
        {
            locations.push(parse_location(l, &host)?);
        }
    }
    if child(node, "upstream").is_some() || child(node, "file-server").is_some() {
        let (sub_filters, sub_max_from) = parse_sub_filters(node, &host)?;
        locations.push(Location {
            matcher: Matcher::Prefix("/".to_string()),
            handler: parse_handler(node, &host)?,
            websocket: child_bool(node, "websocket").unwrap_or(false),
            max_body: parse_max_body(node, &host)?,
            read_timeout: parse_read_timeout(node),
            deny: Vec::new(), // site-wide deny is handled at the site level
            cache: parse_cache(node, &host)?,
            sub_filters,
            sub_max_from,
        });
    }
    if locations.is_empty() {
        return Err(format!(
            "site `{host}`: needs an upstream, a file-server, or at least one location"
        ));
    }

    // A `sub-filter` transforms the body length, which is incompatible with the
    // streaming cache-fill path (the carry-over can't be flushed without a real
    // end-of-stream), so caching is DISABLED at runtime for such a location. Warn
    // so the operator knows the `cache` block has no effect there.
    for loc in &locations {
        if loc.cache.is_some() && !loc.sub_filters.is_empty() {
            log::warn!(
                "site `{host}`: a location has both `cache` and `sub-filter`; caching is \
                 disabled there (a length-changing body rewrite can't be cached correctly). \
                 Remove one of them to silence this."
            );
        }
    }

    let deny = parse_deny(node, &host)?;
    let waf = parse_waf(node, &host)?;
    let acme = child_bool(node, "acme").unwrap_or(false);
    let hsts = child_arg(node, "hsts").map(str::to_owned);
    if let Some(h) = &hsts {
        reject_ctl("hsts", h, &host)?;
    }
    let cloudflare_only = child(node, "access")
        .and_then(|a| prop_bool(a, "cloudflare-only"))
        .unwrap_or(false);

    let rate_limit = match child(node, "rate-limit") {
        Some(r) => {
            // Accept both `rps=50` and `rps=0.5` (the fields are f64).
            let rps = prop_f64(r, "rps").unwrap_or(0.0);
            let burst = prop_f64(r, "burst").unwrap_or(rps);
            if rps <= 0.0 {
                return Err(format!("site `{host}`: rate-limit needs rps > 0"));
            }
            if burst < rps {
                return Err(format!(
                    "site `{host}`: rate-limit burst ({burst}) must be >= rps ({rps})"
                ));
            }
            Some(RateLimit { rps, burst })
        }
        None => None,
    };

    let mut redirects = Vec::new();
    if let Some(children) = node.children() {
        for r in children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "redirect")
        {
            let pat = prop_str(r, "match")
                .ok_or_else(|| format!("site `{host}`: redirect missing match"))?;
            let re = Regex::new(pat)
                .map_err(|e| format!("site `{host}`: redirect regex {pat:?}: {e}"))?;
            let target = prop_str(r, "target")
                .ok_or_else(|| format!("site `{host}`: redirect missing target"))?
                .to_string();
            reject_ctl("redirect target", &target, &host)?;
            let raw_status = prop_int(r, "status").unwrap_or(301);
            let status = u16::try_from(raw_status)
                .ok()
                .filter(|s| (300..=399).contains(s))
                .ok_or_else(|| {
                    format!("site `{host}`: redirect status {raw_status} not in 300..=399")
                })?;
            redirects.push(Redirect { re, target, status });
        }
    }

    // Content-affecting fingerprint → cache namespace (see `Site.cache_epoch`).
    // Every field that can change what bytes an origin returns (or whether they
    // were trust-verified) MUST be included, so a reload that changes it can't
    // keep serving the old config's cached responses. The leading `v3` is a
    // version tag: bump it whenever this format changes to force a clean
    // namespace across an upgrade. (Review findings folded in: `verify`, and the
    // `balance`/`weight` below — changing which backend is selected can change
    // the bytes an origin returns.)
    let mut fp = String::from("v3\u{1f}");
    {
        use std::fmt::Write;
        for loc in &locations {
            match &loc.matcher {
                Matcher::Prefix(p) => {
                    let _ = write!(fp, "P{p}\u{1f}");
                }
                Matcher::Regex(r) => {
                    let _ = write!(fp, "R{}\u{1f}", r.as_str());
                }
            }
            match &loc.handler {
                Handler::Proxy(g) => {
                    let _ = write!(fp, "B{:?}\u{1f}", g.balance);
                    for sv in &g.servers {
                        let _ = write!(
                            fp,
                            "U{}:{}:tls={}:sni={}:verify={}:w={}:host={:?}\u{1f}",
                            sv.host, sv.port, sv.tls, sv.sni, sv.verify, sv.weight, sv.host_header
                        );
                    }
                }
                Handler::File { root, index, .. } => {
                    let _ = write!(fp, "F{root}:{index}\u{1f}");
                }
            }
            let _ = write!(fp, "ws={}:rt={:?}\u{1f}", loc.websocket, loc.read_timeout);
            // Cache policy (TTL + max-object) is part of the namespace too, so a
            // reload that changes the TTL doesn't leave entries bound by the OLD
            // policy (a review finding: `ttl-secs 600`→`1` still served the old
            // entry). Absence vs. a value both fingerprint distinctly.
            if let Some(cc) = &loc.cache {
                let _ = write!(fp, "C{:?}:{}\u{1f}", cc.ttl, cc.max_object);
            } else {
                let _ = write!(fp, "C-\u{1f}");
            }
            for sf in &loc.sub_filters {
                let _ = write!(fp, "S{:?}>{:?}\u{1f}", sf.from, sf.to);
            }
        }
    }
    let cache_epoch = stable_hash(&fp);

    Ok(Site {
        host,
        locations,
        deny,
        waf,
        hsts,
        cloudflare_only,
        rate_limit,
        redirects,
        acme,
        cache_epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // `Config` isn't `Debug`, so extract the error without `unwrap_err`.
    fn parse_err(s: &str) -> String {
        match Config::parse(s) {
            Err(e) => e,
            Ok(_) => panic!("expected a config error"),
        }
    }

    #[test]
    fn h2_idle_timeout_secs_parses_with_default_and_zero_disabled() {
        let site =
            "\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9001\"\n}\n";
        // Absent → default 60s.
        let c = Config::parse(&format!("server {{\n threads 1\n}}{site}")).unwrap();
        assert_eq!(c.server.h2_idle_timeout_secs, 60);
        // Explicit value is honored.
        let c = Config::parse(&format!("server {{\n h2-idle-timeout-secs 15\n}}{site}")).unwrap();
        assert_eq!(c.server.h2_idle_timeout_secs, 15);
        // 0 = disabled (accepted by the schema, unbounded at runtime).
        let c = Config::parse(&format!("server {{\n h2-idle-timeout-secs 0\n}}{site}")).unwrap();
        assert_eq!(c.server.h2_idle_timeout_secs, 0);
    }

    #[test]
    fn downstream_write_timeout_secs_defaults_finite_and_parses() {
        let site =
            "\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9001\"\n}\n";
        // Absent → production-safe finite default (60s), NOT disabled.
        let c = Config::parse(&format!("server {{\n threads 1\n}}{site}")).unwrap();
        assert_eq!(c.server.downstream_write_timeout_secs, 60);
        // Explicit value honored.
        let c = Config::parse(&format!(
            "server {{\n downstream-write-timeout-secs 20\n}}{site}"
        ))
        .unwrap();
        assert_eq!(c.server.downstream_write_timeout_secs, 20);
        // 0 = explicit opt-out (accepted by the schema).
        let c = Config::parse(&format!(
            "server {{\n downstream-write-timeout-secs 0\n}}{site}"
        ))
        .unwrap();
        assert_eq!(c.server.downstream_write_timeout_secs, 0);
    }

    #[test]
    fn h2_handshake_timeout_secs_defaults_finite_and_clamps_to_one() {
        let site =
            "\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9001\"\n}\n";
        // Absent → finite default of 10s.
        let c = Config::parse(&format!("server {{\n threads 1\n}}{site}")).unwrap();
        assert_eq!(c.server.h2_handshake_timeout_secs, 10);
        // Explicit value honored.
        let c = Config::parse(&format!(
            "server {{\n h2-handshake-timeout-secs 3\n}}{site}"
        ))
        .unwrap();
        assert_eq!(c.server.h2_handshake_timeout_secs, 3);
        // The preface deadline must stay FINITE: unlike the idle timeout, 0 is NOT a
        // valid "disabled" value — the schema requires >= 1s and rejects it.
        let e = parse_err(&format!(
            "server {{\n h2-handshake-timeout-secs 0\n}}{site}"
        ));
        assert!(
            e.contains("out of range"),
            "0 handshake timeout must be rejected, got: {e}"
        );
    }

    #[test]
    fn upstream_dns_timeout_secs_defaults_finite_and_rejects_zero() {
        let site =
            "\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9001\"\n}\n";
        let c = Config::parse(&format!("server {{\n threads 1\n}}{site}")).unwrap();
        assert_eq!(c.server.upstream_dns_timeout_secs, 5);
        let c = Config::parse(&format!(
            "server {{\n upstream-dns-timeout-secs 2\n}}{site}"
        ))
        .unwrap();
        assert_eq!(c.server.upstream_dns_timeout_secs, 2);
        // Must stay finite (>= 1s); 0 is rejected by the schema.
        let e = parse_err(&format!(
            "server {{\n upstream-dns-timeout-secs 0\n}}{site}"
        ));
        assert!(
            e.contains("out of range"),
            "0 dns timeout must be rejected: {e}"
        );
    }

    #[test]
    fn tls_handshake_timeout_secs_defaults_finite_and_rejects_zero() {
        let site =
            "\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9001\"\n}\n";
        // Absent → finite default of 10s.
        let c = Config::parse(&format!("server {{\n threads 1\n}}{site}")).unwrap();
        assert_eq!(c.server.tls_handshake_timeout_secs, 10);
        // Explicit value honored.
        let c = Config::parse(&format!(
            "server {{\n tls-handshake-timeout-secs 3\n}}{site}"
        ))
        .unwrap();
        assert_eq!(c.server.tls_handshake_timeout_secs, 3);
        // Must stay finite (>= 1s): 0 is rejected by the schema.
        let e = parse_err(&format!(
            "server {{\n tls-handshake-timeout-secs 0\n}}{site}"
        ));
        assert!(
            e.contains("out of range"),
            "0 tls handshake timeout must be rejected: {e}"
        );
    }

    #[test]
    fn access_log_format_defaults_text_and_validates() {
        let site =
            "\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9001\"\n}\n";
        // Absent → text (backward-compatible default).
        let c = Config::parse(&format!("server {{\n threads 1\n}}{site}")).unwrap();
        assert_eq!(c.server.access_log_format, AccessLogFormat::Text);
        // Explicit values honored.
        let c =
            Config::parse(&format!("server {{\n access-log-format \"json\"\n}}{site}")).unwrap();
        assert_eq!(c.server.access_log_format, AccessLogFormat::Json);
        let c =
            Config::parse(&format!("server {{\n access-log-format \"text\"\n}}{site}")).unwrap();
        assert_eq!(c.server.access_log_format, AccessLogFormat::Text);
        // An unknown value is a strict, actionable error.
        let e = parse_err(&format!("server {{\n access-log-format \"yaml\"\n}}{site}"));
        assert!(
            e.contains("access-log-format") && e.contains("text|json"),
            "unknown access-log-format must be rejected: {e}"
        );
    }

    #[test]
    fn upstream_dns_cache_knobs_default_and_parse() {
        let site =
            "\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9001\"\n}\n";
        // Defaults.
        let c = Config::parse(&format!("server {{\n threads 1\n}}{site}")).unwrap();
        assert_eq!(c.server.upstream_dns_ttl_secs, 30);
        assert_eq!(c.server.upstream_dns_stale_secs, 300);
        assert_eq!(c.server.upstream_dns_max_concurrent, 8);
        // Explicit values.
        let c = Config::parse(&format!(
            "server {{\n upstream-dns-ttl-secs 10\n upstream-dns-stale-secs 0\n upstream-dns-max-concurrent 2\n}}{site}"
        ))
        .unwrap();
        assert_eq!(c.server.upstream_dns_ttl_secs, 10);
        assert_eq!(c.server.upstream_dns_stale_secs, 0); // 0 = never serve stale (allowed)
        assert_eq!(c.server.upstream_dns_max_concurrent, 2);
        // TTL must be >= 1s; max-concurrent must be >= 1 — both reject 0.
        assert!(
            parse_err(&format!("server {{\n upstream-dns-ttl-secs 0\n}}{site}"))
                .contains("out of range")
        );
        assert!(parse_err(&format!(
            "server {{\n upstream-dns-max-concurrent 0\n}}{site}"
        ))
        .contains("out of range"));
    }

    #[test]
    fn upstream_rejects_over_long_dns_labels_and_names() {
        // A single label over 63 bytes (total name still under 253) → rejected.
        let long_label = "a".repeat(64);
        let e = parse_upstream(&format!("{long_label}.example:80")).unwrap_err();
        assert!(
            e.contains("63-byte limit"),
            "over-long label must be rejected: {e}"
        );
        // A whole name over 253 bytes (built from valid <=63-byte labels) → rejected.
        let big_name = std::iter::repeat_n("abcdefghij", 30)
            .collect::<Vec<_>>()
            .join("."); // 30*10 + 29 dots = 329 bytes, each label 10 bytes
        let e = parse_upstream(&format!("{big_name}:80")).unwrap_err();
        assert!(
            e.contains("253-byte DNS name limit"),
            "over-long name must be rejected: {e}"
        );
        // Boundary: a label of exactly 63 bytes and a name of exactly 253 bytes are OK.
        let label_63 = "a".repeat(63);
        assert!(parse_upstream(&format!("{label_63}.io:80")).is_ok());
        // Build a name of exactly 253 bytes: labels of 63,63,63,61 + 3 dots.
        let name_253 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(name_253.len(), 253);
        assert!(
            parse_upstream(&format!("{name_253}:80")).is_ok(),
            "a 253-byte name must be accepted"
        );
    }

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("32MiB").unwrap(), 32 * 1024 * 1024);
        assert_eq!(parse_size("10GB").unwrap(), 10_000_000_000);
        assert_eq!(parse_size("512KB").unwrap(), 512_000);
        assert!(parse_size("nope").is_err());
    }

    #[test]
    fn upstream_host_header_authority_brackets_v6_and_keeps_nondefault_port() {
        let up = |s: &str| parse_upstream(s).unwrap();
        // IPv4 with a non-default port: the Host must carry the port (the bug
        // dropped it, sending `Host: 127.0.0.1`).
        let u = up("http://127.0.0.1:19002");
        assert_eq!(u.host, "127.0.0.1");
        assert_eq!(u.port, 19002);
        assert_eq!(u.host_header.as_deref(), Some("127.0.0.1:19002"));
        // IPv6 literal: Host must stay BRACKETED and keep the non-default port
        // (the bug sent `Host: ::1`, an invalid unbracketed authority).
        let u = up("http://[::1]:19003");
        assert_eq!(u.host, "::1"); // dial/SNI use the bracketless host
        assert_eq!(u.host_header.as_deref(), Some("[::1]:19003"));
        // Default port is omitted per RFC 9110 §7.2.
        assert_eq!(
            up("https://api.example.com").host_header.as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            up("https://api.example.com:443").host_header.as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            up("http://api.example.com:80").host_header.as_deref(),
            Some("api.example.com")
        );
        // Non-default port on a hostname is kept.
        assert_eq!(
            up("https://api.example.com:8443").host_header.as_deref(),
            Some("api.example.com:8443")
        );
        // IPv6 with the default port stays bracketed, no port.
        assert_eq!(up("http://[::1]").host_header.as_deref(), Some("[::1]"));
        // Bare host:port preserves the client's Host (no override).
        assert_eq!(up("127.0.0.1:9000").host_header, None);
        assert_eq!(up("[::1]:9000").host_header, None);
    }

    #[test]
    fn stable_hash_deterministic_and_avalanches() {
        assert_eq!(stable_hash("abc"), stable_hash("abc"));
        // Adjacent ring-point strings must land far apart (good avalanche) —
        // plain FNV failed this and skewed the ketama distribution.
        let a = stable_hash("127.0.0.1:8080-0");
        let b = stable_hash("127.0.0.1:8080-1");
        assert_ne!(a, b);
        assert!((a ^ b).count_ones() > 20, "weak avalanche: {a:x} vs {b:x}");
    }

    #[test]
    fn ketama_ring_points_scale_with_weight() {
        let mk = |host: &str, w: u32| Upstream {
            host: host.into(),
            port: 80,
            tls: false,
            sni: host.into(),
            host_header: None,
            verify: false,
            weight: w,
        };
        let ring = build_ketama_ring(&[mk("a", 3), mk("b", 1)]);
        let a = ring.iter().filter(|(_, i)| *i == 0).count();
        let b = ring.iter().filter(|(_, i)| *i == 1).count();
        assert_eq!(a, 480);
        assert_eq!(b, 160);
    }

    #[test]
    fn rejects_unknown_directive() {
        let e = parse_err(
            "server {\n threds 4\n}\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n",
        );
        assert!(e.contains("unknown directive `threds`"), "{e}");
    }

    #[test]
    fn rejects_ketama_weight_over_1000() {
        let e = parse_err(
            "listener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream {\n server \"127.0.0.1:9\" weight=5000\n balance \"ketama\"\n }\n}\n",
        );
        assert!(e.contains("weight must be 1..=1000"), "{e}");
    }

    // A minimal valid config the strict-schema tests can splice a bad line into.
    fn cfg_with(site_body: &str) -> String {
        format!(
            "listener \"0.0.0.0:80\" {{\n redirect-to-https true\n}}\nsite \"x\" {{\n{site_body}\n}}\n"
        )
    }

    #[test]
    fn strict_schema_rejects_stray_props_and_dups() {
        // Props on value-only leaves / blocks.
        assert!(parse_err("server {\n threads 2 typo=true\n}\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n").contains("unknown property"));
        assert!(parse_err(&cfg_with(
            " max-body \"1MiB\" typo=true\n upstream \"127.0.0.1:9\""
        ))
        .contains("property"));
        assert!(parse_err(&cfg_with(" upstream \"127.0.0.1:9\" typo=true"))
            .contains("unknown property"));
        // Duplicate singleton leaves / blocks.
        assert!(parse_err("server {\n threads 2\n threads 4\n}\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n").contains("given more than once"));
        assert!(parse_err(&cfg_with(
            " websocket true\n websocket true\n upstream \"127.0.0.1:9\""
        ))
        .contains("given more than once"));
        assert!(parse_err(&cfg_with(
            " cache {\n ttl-secs 1\n ttl-secs 2\n}\n upstream \"127.0.0.1:9\""
        ))
        .contains("given more than once"));
        assert!(parse_err(&cfg_with(
            " upstream {\n server \"127.0.0.1:9\"\n balance \"random\"\n balance \"ketama\"\n }"
        ))
        .contains("given more than once"));
    }

    #[test]
    fn strict_schema_rejects_bad_args_and_nonfinite() {
        // Extra positional argument.
        assert!(parse_err(&cfg_with(
            " max-body \"1mb\" \"2mb\"\n upstream \"127.0.0.1:9\""
        ))
        .contains("argument"));
        assert!(parse_err("listener \"0.0.0.0:80\" \"extra\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n").contains("argument"));
        // Non-finite float in a numeric prop must not silently become +inf.
        assert!(parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\"\n rate-limit rps=1.0e999 burst=1.0e999"
        ))
        .contains("must be a number"));
    }

    #[test]
    fn strict_schema_rejects_round5_cases() {
        // server block takes no positional; threads takes exactly one arg.
        let e = parse_err("server \"ignored\" {\n threads 2 3\n}\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n");
        assert!(e.contains("server: expected exactly 0"), "{e}");
        assert!(e.contains("threads: expected exactly 1"), "{e}");
        // upstream shorthand with an extra positional / mixed with a block.
        assert!(parse_err(&cfg_with(" upstream \"127.0.0.1:9\" \"ignored\"")).contains("argument"));
        assert!(parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\" {\n server \"127.0.0.1:10\"\n }"
        ))
        .contains("not both"));
        // health-check takes no positional; path takes exactly one.
        let e = parse_err(&cfg_with(
            " upstream {\n server \"127.0.0.1:9\"\n health-check \"ignored\" {\n path \"/health\" \"ignored\"\n }\n }"
        ));
        assert!(e.contains("health-check: expected exactly 0"), "{e}");
        assert!(e.contains("path: expected exactly 1"), "{e}");
        // rate-limit takes neither positionals nor a block.
        let e = parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\"\n rate-limit \"ignored\" rps=1 burst=1 {\n typo true\n }",
        ));
        assert!(e.contains("argument"), "{e}");
        assert!(e.contains("takes no block"), "{e}");
        // tls: no positionals; `acme=true` conflicts with `key=`.
        assert!(parse_err("listener \"0.0.0.0:443\" {\n tls \"ignored\" acme=true\n}\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n").contains("argument"));
        assert!(parse_err("listener \"0.0.0.0:443\" {\n tls acme=true key=\"/missing.key\"\n}\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n").contains("can't be combined"));
        // sub-filter to= must be a string (was silently coerced to "").
        assert!(parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\"\n sub-filter from=\"a\" to=123"
        ))
        .contains("must be a quoted string"));
        // waf takes no props; a waf block takes no children.
        let e = parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\"\n waf typo=true {\n block field=\"query\" match=\"x\" {\n typo true\n }\n }"
        ));
        assert!(e.contains("waf: unknown property"), "{e}");
        assert!(e.contains("takes no block"), "{e}");
        // duplicate property on one node.
        assert!(parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\"\n rate-limit rps=1 rps=2 burst=2"
        ))
        .contains("duplicate property"));
        // alias was removed entirely (its canonicalization leaked cache entries
        // across Hosts) — it is now an unknown directive.
        assert!(parse_err("alias prefix=\"s\"\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n").contains("unknown top-level directive"));
        assert!(
            parse_err(&cfg_with(" upstream \"127.0.0.1:9\"\n deny \"a\" \"b\""))
                .contains("argument")
        );
    }

    #[test]
    fn strict_schema_rejects_round6_value_semantics() {
        // Negative / oversized integers were silently clamped or narrowed.
        assert!(parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\"\n cache {\n ttl-secs -1\n }"
        ))
        .contains("out of range"));
        assert!(parse_err(&cfg_with(
            " upstream {\n server \"127.0.0.1:9\"\n health-check {\n interval-secs -1\n }\n }"
        ))
        .contains("out of range"));
        // healthy 4294967296 used to narrow to 0 via `as u32` → instant-UP.
        assert!(parse_err(&cfg_with(
            " upstream {\n server \"127.0.0.1:9\"\n health-check {\n healthy 4294967296\n }\n }"
        ))
        .contains("out of range"));
        assert!(parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\"\n read-timeout-secs -1"
        ))
        .contains("out of range"));
        assert!(
            parse_err("server {\n upstream-keepalive-pool -1\n}\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n")
                .contains("out of range")
        );
        // Host semantics: empty is rejected; case variants normalize and so
        // collide as duplicates.
        assert!(parse_err(
            "listener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"\" {\n upstream \"127.0.0.1:9\"\n}\n"
        )
        .contains("host must not be empty"));
        let e = parse_err(
            "listener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"App.Test\" {\n upstream \"127.0.0.1:9\"\n}\nsite \"app.test\" {\n upstream \"127.0.0.1:9\"\n}\n",
        );
        assert!(e.contains("duplicate site host"), "{e}");
        // Uppercase alone is accepted but normalized to lowercase.
        let c = Config::parse(
            "listener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"SMOKE.Example\" {\n upstream \"127.0.0.1:9\"\n}\n",
        )
        .expect("uppercase host should normalize");
        assert!(c.index.contains_key("smoke.example"));
        // CRLF / control bytes in header-bound values.
        assert!(parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\"\n hsts \"max-age=1\\r\\nSet-Cookie: x\""
        ))
        .contains("control characters"));
        assert!(parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\"\n upstream-host \"evil\\r\\nX: y\""
        ))
        .contains("control characters"));
        assert!(parse_err(&cfg_with(
            " upstream {\n server \"127.0.0.1:9\"\n health-check {\n path \"no-slash\"\n }\n }"
        ))
        .contains("must start with '/'"));
    }

    #[test]
    fn cache_epoch_tracks_content_affecting_config() {
        let base = "listener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9001\"\n}\n";
        let same = Config::parse(base).unwrap();
        let again = Config::parse(base).unwrap();
        // Identical config → identical epoch (disk cache survives restarts).
        assert_eq!(same.sites[0].cache_epoch, again.sites[0].cache_epoch);
        // A different upstream → different epoch (old entries unreachable).
        let moved = Config::parse(
            "listener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9002\"\n}\n",
        )
        .unwrap();
        assert_ne!(same.sites[0].cache_epoch, moved.sites[0].cache_epoch);
        // A different sub-filter → different epoch (bodies are transformed).
        let filtered = Config::parse(
            "listener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9001\"\n sub-filter from=\"a\" to=\"b\"\n}\n",
        )
        .unwrap();
        assert_ne!(same.sites[0].cache_epoch, filtered.sites[0].cache_epoch);
        // upstream-verify false→true MUST change the epoch (was a review gap:
        // switching to cert-verifying kept serving previously-unverified cache).
        let mk = |verify: bool| {
            Config::parse(&format!(
                "listener \"0.0.0.0:80\" {{\n redirect-to-https true\n}}\nsite \"x\" {{\n upstream \"https://api.test\"\n upstream-verify {verify}\n}}\n",
            ))
            .unwrap()
        };
        assert_ne!(
            mk(false).sites[0].cache_epoch,
            mk(true).sites[0].cache_epoch,
            "upstream-verify must be part of the cache namespace"
        );
        // TTL / max-object are policy that must also namespace the cache: a
        // reload changing the TTL must not keep serving entries under the old
        // policy (review finding).
        let ttl = |secs: u32| {
            Config::parse(&format!(
                "listener \"0.0.0.0:80\" {{\n redirect-to-https true\n}}\nsite \"x\" {{\n upstream \"127.0.0.1:9\"\n cache {{\n ttl-secs {secs}\n }}\n}}\n",
            ))
            .unwrap()
        };
        assert_ne!(
            ttl(600).sites[0].cache_epoch,
            ttl(1).sites[0].cache_epoch,
            "cache TTL must be part of the namespace"
        );
        // balance policy and backend weight change which origin is selected → epoch.
        let pool = |extra: &str| {
            Config::parse(&format!(
                "listener \"0.0.0.0:80\" {{\n redirect-to-https true\n}}\nsite \"x\" {{\n upstream {{\n server \"127.0.0.1:9001\"{extra}\n server \"127.0.0.1:9002\"\n }}\n}}\n",
            ))
            .unwrap()
        };
        assert_ne!(
            pool("\n balance \"round-robin\"").sites[0].cache_epoch,
            pool("\n balance \"least-conn\"").sites[0].cache_epoch,
            "balance policy must be part of the namespace"
        );
        assert_ne!(
            pool(" weight=1").sites[0].cache_epoch,
            pool(" weight=10").sites[0].cache_epoch,
            "backend weight must be part of the namespace"
        );
    }

    #[test]
    fn strict_schema_rejects_round8_silent_values() {
        // geoip log-fields typo (was silently dropped at request time).
        assert!(parse_err("geoip {\n log-fields \"counrty\"\n}\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n").contains("unknown field"));
        // waf field="header:" (empty header name → dead rule).
        assert!(parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\"\n waf {\n block field=\"header:\" match=\"x\"\n }"
        ))
        .contains("invalid header name"));
        // upstream-host with a space (would corrupt the Host header).
        assert!(parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\"\n upstream-host \"bad host\""
        ))
        .contains("not a valid host"));
    }

    #[test]
    fn strict_schema_rejects_round9_silent_values() {
        // waf header name must be a valid RFC-7230 token (space → dead rule).
        assert!(parse_err(&cfg_with(
            " upstream \"127.0.0.1:9\"\n waf {\n block field=\"header:bad name\" match=\"x\"\n }"
        ))
        .contains("invalid header name"));
        // upstream URL: space in authority, dropped path, and userinfo.
        assert!(parse_err(&cfg_with(" upstream \"https://bad host\"")).contains("invalid host"));
        assert!(parse_err(&cfg_with(" upstream \"https://api.test/v1\"")).contains("path"));
        assert!(
            parse_err(&cfg_with(" upstream \"https://user@api.test\"")).contains("invalid host")
        );
    }

    #[test]
    fn strict_schema_rejects_round10_silent_values() {
        // upstream: query, fragment, path in the BARE form, and port 0.
        assert!(
            parse_err(&cfg_with(" upstream \"https://api.test?x=1\"")).contains("query/fragment")
        );
        assert!(
            parse_err(&cfg_with(" upstream \"https://api.test#frag\"")).contains("query/fragment")
        );
        assert!(parse_err(&cfg_with(" upstream \"127.0.0.1:9/path\"")).contains("path"));
        assert!(parse_err(&cfg_with(" upstream \"127.0.0.1:0\"")).contains("port 0"));
    }

    #[test]
    fn strict_schema_rejects_round11_values() {
        // upstream: bare trailing slash, %-encoded host, leading-dash host.
        assert!(parse_err(&cfg_with(" upstream \"127.0.0.1:9/\"")).contains("trailing-slash"));
        assert!(parse_err(&cfg_with(" upstream \"https://api%2etest\"")).contains("invalid host"));
        assert!(parse_err(&cfg_with(" upstream \"https://-bad.test\"")).contains("invalid host"));
        // …but a real IPv6 upstream and a normal https origin still parse.
        assert!(Config::parse(&cfg_with(" upstream \"[2001:db8::1]:443\"")).is_ok());
        assert!(Config::parse(&cfg_with(" upstream \"https://api.test/\"")).is_ok());
        // IPv6 wildcard `[::]:P` conflicts with an IPv4 same-port listener (dual
        // stack binds v4 too) — SocketAddr equality / same-family missed it.
        let v6 = "listener \"[::]:29580\" {\n redirect-to-https true\n}\nlistener \"0.0.0.0:29580\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n";
        assert!(
            parse_err(v6).contains("conflicting listener"),
            "{}",
            parse_err(v6)
        );
    }

    #[test]
    fn wildcard_listener_and_metrics_conflicts() {
        // 0.0.0.0:P already binds 127.0.0.1:P — must be flagged (plain
        // SocketAddr equality let this pair through).
        let dup = "listener \"0.0.0.0:28580\" {\n redirect-to-https true\n}\nlistener \"127.0.0.1:28580\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n";
        assert!(
            parse_err(dup).contains("conflicting listener"),
            "{}",
            parse_err(dup)
        );
        // metrics on a wildcard-overlapping listener port.
        let m = "server {\n metrics-addr \"127.0.0.1:28580\"\n}\nlistener \"0.0.0.0:28580\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n";
        assert!(parse_err(m).contains("collides"), "{}", parse_err(m));
        // A different port is fine.
        let ok = "server {\n metrics-addr \"127.0.0.1:28581\"\n}\nlistener \"0.0.0.0:28580\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n";
        assert!(Config::parse(ok).is_ok());
    }

    #[test]
    fn file_server_index_must_be_a_basename() {
        // `index "../Cargo.toml"` used to pass --check and escape the docroot.
        // Use a real docroot (`src` exists in the crate root, where tests run) so
        // the docroot-fd open succeeds and index validation is reached.
        let bad = "listener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n file-server {\n root \"src\"\n index \"../Cargo.toml\"\n }\n}\n";
        assert!(
            parse_err(bad).contains("plain filename"),
            "{}",
            parse_err(bad)
        );
        let abs = "listener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n file-server {\n root \"src\"\n index \"/etc/passwd\"\n }\n}\n";
        assert!(parse_err(abs).contains("plain filename"));
    }

    #[test]
    fn rate_limit_accepts_float() {
        // rps=0.5 must parse and be stored (not rejected as "needs rps > 0").
        let c = Config::parse(
            "listener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n rate-limit rps=0.5 burst=1\n}\n",
        )
        .expect("float rps should parse");
        assert_eq!(c.sites[0].rate_limit.unwrap().rps, 0.5);
    }

    #[test]
    fn rate_limit_rejects_burst_below_rps() {
        let e = parse_err(
            "listener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n rate-limit rps=50 burst=10\n}\n",
        );
        assert!(e.contains("burst"), "{e}");
    }

    #[test]
    fn duplicate_singleton_block_errors() {
        let e = parse_err(
            "server {\n threads 1\n}\nserver {\n threads 2\n}\nlistener \"0.0.0.0:80\" {\n redirect-to-https true\n}\nsite \"x\" {\n upstream \"127.0.0.1:9\"\n}\n",
        );
        assert!(e.contains("duplicate `server` block"), "{e}");
    }
}

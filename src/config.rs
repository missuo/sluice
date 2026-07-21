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
    pub alias_prefix: Option<String>,
    pub acme: Option<AcmeCfg>,
    /// Disk-backed response cache (None = the default in-memory LRU).
    pub disk_cache: Option<DiskCacheCfg>,
    pub unknown_host: u16,
    pub sites: Vec<Site>,
    /// host -> index into `sites`
    pub index: HashMap<String, usize>,
}

#[derive(Debug)]
pub struct ServerCfg {
    pub threads: usize,
    pub metrics_addr: Option<String>,
    pub grace_period_secs: u64,
    pub graceful_shutdown_secs: u64,
    pub upstream_keepalive_pool: usize,
    pub upgrade_sock: Option<String>,
}

impl Default for ServerCfg {
    fn default() -> Self {
        ServerCfg {
            threads: 0, // 0 = all cores (resolved in main)
            metrics_addr: None,
            grace_period_secs: 30,
            graceful_shutdown_secs: 300,
            upstream_keepalive_pool: 256,
            upgrade_sock: None,
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

#[derive(Debug, Clone)]
pub struct Listener {
    pub addr: String,
    pub kind: ListenerKind,
}

#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
    File { root: String, index: String },
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

/// Push an error for any child directive whose name isn't in `allowed` — so a
/// typo (`threds`, `cahce`, `interval-sec`) is a config error, not a silent
/// no-op. This is the nested-block equivalent of the top-level unknown check.
fn reject_unknown_children(node: &KdlNode, ctx: &str, allowed: &[&str], errs: &mut Vec<String>) {
    if let Some(ch) = node.children() {
        for n in ch.nodes() {
            let name = n.name().value();
            if !allowed.contains(&name) {
                errs.push(format!("{ctx}: unknown directive `{name}`"));
            }
        }
    }
}
/// Push an error for any `key=value` property whose key isn't in `allowed`.
fn reject_unknown_props(node: &KdlNode, ctx: &str, allowed: &[&str], errs: &mut Vec<String>) {
    for e in node.entries() {
        if let Some(k) = e.name() {
            let name = k.value();
            if !allowed.contains(&name) {
                errs.push(format!("{ctx}: unknown property `{name}`"));
            }
        }
    }
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
            Ty::Num => v.as_integer().is_some() || v.as_float().is_some(),
            Ty::Bool => v.as_bool().is_some(),
            Ty::Str => v.as_string().is_some(),
        }
    }
}

/// Error when a known child directive is present but its value is the wrong type
/// (e.g. `threads "four"`, `max-body 1024`) — which otherwise silently defaults.
fn check_child_types(node: &KdlNode, ctx: &str, specs: &[(&str, Ty)], errs: &mut Vec<String>) {
    for (name, ty) in specs {
        let Some(c) = child(node, name) else { continue };
        let val = c
            .entries()
            .iter()
            .find(|e| e.name().is_none())
            .map(|e| e.value());
        let ok = matches!(val, Some(v) if ty.matches(v));
        if !ok {
            errs.push(format!("{ctx}: `{name}` must be {}", ty.describe()));
        }
    }
}

/// Error when a known property is present but its value is the wrong type
/// (e.g. `cloudflare-only="true"`, a string where a bool is meant).
fn check_prop_types(node: &KdlNode, ctx: &str, specs: &[(&str, Ty)], errs: &mut Vec<String>) {
    for (name, ty) in specs {
        let Some(v) = node.get(*name) else { continue };
        if !ty.matches(v) {
            errs.push(format!(
                "{ctx}: property `{name}` must be {}",
                ty.describe()
            ));
        }
    }
}

/// Error when a directive that may appear at most once is repeated.
fn reject_dup_children(node: &KdlNode, ctx: &str, singletons: &[&str], errs: &mut Vec<String>) {
    if let Some(ch) = node.children() {
        for name in singletons {
            if ch
                .nodes()
                .iter()
                .filter(|n| n.name().value() == *name)
                .count()
                > 1
            {
                errs.push(format!("{ctx}: `{name}` given more than once"));
            }
        }
    }
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
    let hostport = rest.split('/').next().unwrap_or(rest);
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
    Ok(Upstream {
        sni: host.clone(),
        host_header: if url_form { Some(host.clone()) } else { None },
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

// ---- unknown-directive validation (nested blocks; top level is checked inline) ----

fn validate_unknowns(doc: &KdlDocument, errs: &mut Vec<String>) {
    // Only one of each of these top-level blocks makes sense; a second silently
    // won last-wins (or merged) before.
    const SINGLETONS: &[&str] = &[
        "server",
        "client-ip",
        "geoip",
        "acme",
        "cache-store",
        "alias",
        "defaults",
    ];
    let mut seen: Vec<&str> = Vec::new();
    for node in doc.nodes() {
        let name = node.name().value();
        if SINGLETONS.contains(&name) {
            if seen.contains(&name) {
                errs.push(format!("duplicate `{name}` block (only one allowed)"));
            } else {
                seen.push(name);
            }
        }
        match name {
            "server" => {
                reject_unknown_children(
                    node,
                    "server",
                    &[
                        "threads",
                        "metrics-addr",
                        "grace-period-secs",
                        "graceful-shutdown-secs",
                        "upstream-keepalive-pool",
                        "upgrade-sock",
                    ],
                    errs,
                );
                check_child_types(
                    node,
                    "server",
                    &[
                        ("threads", Ty::Int),
                        ("metrics-addr", Ty::Str),
                        ("grace-period-secs", Ty::Int),
                        ("graceful-shutdown-secs", Ty::Int),
                        ("upstream-keepalive-pool", Ty::Int),
                        ("upgrade-sock", Ty::Str),
                    ],
                    errs,
                );
            }
            "client-ip" => {
                reject_unknown_children(
                    node,
                    "client-ip",
                    &["trusted-header", "trusted-proxies"],
                    errs,
                );
                check_child_types(node, "client-ip", &[("trusted-header", Ty::Str)], errs);
            }
            "geoip" => {
                reject_unknown_children(
                    node,
                    "geoip",
                    &[
                        "enabled",
                        "country-header",
                        "mmdb-asn",
                        "mmdb-city",
                        "log-fields",
                        "metric-labels",
                    ],
                    errs,
                );
                check_child_types(
                    node,
                    "geoip",
                    &[
                        ("enabled", Ty::Bool),
                        ("country-header", Ty::Str),
                        ("mmdb-asn", Ty::Str),
                        ("mmdb-city", Ty::Str),
                    ],
                    errs,
                );
            }
            "acme" => {
                reject_unknown_children(
                    node,
                    "acme",
                    &["enabled", "contact", "staging", "cache-dir"],
                    errs,
                );
                check_child_types(
                    node,
                    "acme",
                    &[
                        ("enabled", Ty::Bool),
                        ("staging", Ty::Bool),
                        ("cache-dir", Ty::Str),
                    ],
                    errs,
                );
            }
            "cache-store" => reject_unknown_children(
                node,
                "cache-store",
                &["dir", "max-size", "max-files", "min-free"],
                errs,
            ),
            "defaults" => {
                reject_unknown_children(node, "defaults", &["hsts", "unknown-host"], errs);
                check_child_types(
                    node,
                    "defaults",
                    &[("hsts", Ty::Str), ("unknown-host", Ty::Int)],
                    errs,
                );
            }
            "alias" => reject_unknown_props(node, "alias", &["prefix"], errs),
            "listener" => {
                // A listener takes only its bind-address argument — reject `typo=true`.
                reject_unknown_props(node, "listener", &[], errs);
                reject_unknown_children(
                    node,
                    "listener",
                    &["http2", "tls", "redirect-to-https"],
                    errs,
                );
                check_child_types(
                    node,
                    "listener",
                    &[("http2", Ty::Bool), ("redirect-to-https", Ty::Bool)],
                    errs,
                );
                if let Some(tls) = child(node, "tls") {
                    reject_unknown_props(
                        tls,
                        "listener tls",
                        &["cert", "key", "cert-dir", "acme"],
                        errs,
                    );
                }
            }
            "site" => validate_site_unknowns(node, errs),
            _ => {}
        }
    }
}

const SITE_CHILDREN: &[&str] = &[
    "location",
    "upstream",
    "file-server",
    "deny",
    "redirect",
    "rate-limit",
    "access",
    "waf",
    "hsts",
    "acme",
    "websocket",
    "max-body",
    "read-timeout-secs",
    "upstream-host",
    "upstream-verify",
    "sub-filter",
    "cache",
];
const LOCATION_CHILDREN: &[&str] = &[
    "upstream",
    "file-server",
    "websocket",
    "max-body",
    "read-timeout-secs",
    "deny",
    "cache",
    "sub-filter",
    "upstream-host",
    "upstream-verify",
];

/// Directives shared by a site and a location that must appear at most once.
const SINGLE_HANDLER_CHILDREN: &[&str] = &[
    "upstream",
    "file-server",
    "cache",
    "rate-limit",
    "access",
    "waf",
    "max-body",
    "websocket",
    "read-timeout-secs",
    "hsts",
    "upstream-host",
    "upstream-verify",
    "acme",
];
/// Typed leaf fields shared by a site and a location.
const HANDLER_FIELD_TYPES: &[(&str, Ty)] = &[
    ("websocket", Ty::Bool),
    ("max-body", Ty::Str),
    ("read-timeout-secs", Ty::Int),
    ("upstream-host", Ty::Str),
    ("upstream-verify", Ty::Bool),
    ("hsts", Ty::Str),
    ("acme", Ty::Bool),
];

fn validate_site_unknowns(node: &KdlNode, errs: &mut Vec<String>) {
    let host = first_arg(node).unwrap_or("?");
    let ctx = format!("site `{host}`");
    reject_unknown_children(node, &ctx, SITE_CHILDREN, errs);
    // A site takes only a host argument — reject stray props like `typo=true`.
    reject_unknown_props(node, &ctx, &[], errs);
    reject_dup_children(node, &ctx, SINGLE_HANDLER_CHILDREN, errs);
    check_child_types(node, &ctx, HANDLER_FIELD_TYPES, errs);
    let Some(children) = node.children() else {
        return;
    };
    for n in children.nodes() {
        match n.name().value() {
            "location" => {
                let lctx = format!("{ctx} location");
                reject_unknown_children(n, &lctx, LOCATION_CHILDREN, errs);
                // A location takes only a matcher argument — reject `typo=true`.
                reject_unknown_props(n, &lctx, &[], errs);
                reject_dup_children(n, &lctx, SINGLE_HANDLER_CHILDREN, errs);
                check_child_types(n, &lctx, HANDLER_FIELD_TYPES, errs);
                if let Some(lch) = n.children() {
                    for c in lch.nodes() {
                        let cn = c.name().value();
                        if VALUE_ONLY_LEAVES.contains(&cn) {
                            reject_unknown_props(c, &format!("{lctx} {cn}"), &[], errs);
                        }
                    }
                }
                validate_backend_unknowns(n, &ctx, errs);
            }
            "upstream" | "file-server" | "cache" | "rate-limit" | "access" | "waf" | "redirect"
            | "sub-filter" => validate_backend_child(n, &ctx, errs),
            name if VALUE_ONLY_LEAVES.contains(&name) => {
                // e.g. `max-body "10mb" typo=true` — the leaf takes only its value.
                reject_unknown_props(n, &format!("{ctx} {name}"), &[], errs);
            }
            _ => {}
        }
    }
    // The site-level backend sugar (upstream/file-server/cache/...) at the site node.
    validate_backend_unknowns(node, &ctx, errs);
}

/// Value-only leaf directives: they take exactly one argument and no properties.
const VALUE_ONLY_LEAVES: &[&str] = &[
    "max-body",
    "websocket",
    "read-timeout-secs",
    "hsts",
    "upstream-host",
    "upstream-verify",
    "acme",
];

/// Validate the backend/handler-shaped children shared by a site and a location.
fn validate_backend_unknowns(node: &KdlNode, ctx: &str, errs: &mut Vec<String>) {
    if let Some(u) = child(node, "upstream") {
        validate_backend_child(u, ctx, errs);
    }
    if let Some(f) = child(node, "file-server") {
        validate_backend_child(f, ctx, errs);
    }
    if let Some(c) = child(node, "cache") {
        validate_backend_child(c, ctx, errs);
    }
}

fn validate_backend_child(n: &KdlNode, ctx: &str, errs: &mut Vec<String>) {
    match n.name().value() {
        "upstream" => {
            reject_unknown_children(
                n,
                &format!("{ctx} upstream"),
                &["server", "balance", "health-check"],
                errs,
            );
            if let Some(ch) = n.children() {
                for s in ch.nodes().iter().filter(|x| x.name().value() == "server") {
                    reject_unknown_props(s, &format!("{ctx} upstream server"), &["weight"], errs);
                    check_prop_types(
                        s,
                        &format!("{ctx} upstream server"),
                        &[("weight", Ty::Int)],
                        errs,
                    );
                }
            }
            if let Some(hc) = child(n, "health-check") {
                let hctx = format!("{ctx} health-check");
                reject_unknown_children(
                    hc,
                    &hctx,
                    &[
                        "path",
                        "interval-secs",
                        "timeout-secs",
                        "healthy",
                        "unhealthy",
                        "expect-status",
                    ],
                    errs,
                );
                check_child_types(
                    hc,
                    &hctx,
                    &[
                        ("path", Ty::Str),
                        ("interval-secs", Ty::Int),
                        ("timeout-secs", Ty::Int),
                        ("healthy", Ty::Int),
                        ("unhealthy", Ty::Int),
                        ("expect-status", Ty::Int),
                    ],
                    errs,
                );
            }
        }
        "file-server" => {
            let fctx = format!("{ctx} file-server");
            reject_unknown_children(n, &fctx, &["root", "index"], errs);
            reject_unknown_props(n, &fctx, &[], errs);
            check_child_types(n, &fctx, &[("root", Ty::Str), ("index", Ty::Str)], errs);
            // `root "/tmp" typo=true` — root/index take only their value.
            if let Some(ch) = n.children() {
                for c in ch.nodes() {
                    let cn = c.name().value();
                    if cn == "root" || cn == "index" {
                        reject_unknown_props(c, &format!("{fctx} {cn}"), &[], errs);
                    }
                }
            }
        }
        "cache" => {
            reject_unknown_children(
                n,
                &format!("{ctx} cache"),
                &["ttl-secs", "max-object"],
                errs,
            );
            check_child_types(
                n,
                &format!("{ctx} cache"),
                &[("ttl-secs", Ty::Int), ("max-object", Ty::Str)],
                errs,
            );
        }
        "rate-limit" => {
            reject_unknown_props(n, &format!("{ctx} rate-limit"), &["rps", "burst"], errs);
            check_prop_types(
                n,
                &format!("{ctx} rate-limit"),
                &[("rps", Ty::Num), ("burst", Ty::Num)],
                errs,
            );
        }
        "access" => {
            reject_unknown_props(n, &format!("{ctx} access"), &["cloudflare-only"], errs);
            check_prop_types(
                n,
                &format!("{ctx} access"),
                &[("cloudflare-only", Ty::Bool)],
                errs,
            );
        }
        "redirect" => {
            reject_unknown_props(
                n,
                &format!("{ctx} redirect"),
                &["match", "target", "status"],
                errs,
            );
            check_prop_types(
                n,
                &format!("{ctx} redirect"),
                &[("match", Ty::Str), ("target", Ty::Str), ("status", Ty::Int)],
                errs,
            );
        }
        "sub-filter" => {
            reject_unknown_props(n, &format!("{ctx} sub-filter"), &["from", "to"], errs)
        }
        "waf" => {
            // A `waf` block contains only `block` directives — catch e.g. `blok`,
            // which would otherwise leave the WAF with no rules.
            reject_unknown_children(n, &format!("{ctx} waf"), &["block"], errs);
            if let Some(ch) = n.children() {
                for b in ch.nodes().iter().filter(|x| x.name().value() == "block") {
                    reject_unknown_props(
                        b,
                        &format!("{ctx} waf block"),
                        &["field", "match", "status"],
                        errs,
                    );
                    check_prop_types(
                        b,
                        &format!("{ctx} waf block"),
                        &[("field", Ty::Str), ("match", Ty::Str), ("status", Ty::Int)],
                        errs,
                    );
                }
            }
        }
        _ => {}
    }
}

const TOP_LEVEL: &[&str] = &[
    "server",
    "client-ip",
    "geoip",
    "acme",
    "cache-store",
    "listener",
    "alias",
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
        let mut alias_prefix = None;
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
                "alias" => match prop_str(node, "prefix").filter(|p| !p.is_empty()) {
                    Some(p) => alias_prefix = Some(p.to_string()),
                    // `alias "staging"` (positional) or `alias prefix=""` silently
                    // disabled aliasing before — make it an explicit error.
                    None => {
                        errs.push("alias: needs a non-empty prefix=\"...\" property".to_string())
                    }
                },
                "acme" => {
                    let enabled = child_bool(node, "enabled").unwrap_or(true);
                    if enabled {
                        match child_arg(node, "contact") {
                            Some(c) => {
                                acme = Some(AcmeCfg {
                                    contact: c.to_string(),
                                    staging: child_bool(node, "staging").unwrap_or(false),
                                    cache_dir: child_arg(node, "cache-dir")
                                        .unwrap_or("/var/lib/sluice/acme")
                                        .to_string(),
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
                        // Surface an unusable dir now (create it if missing),
                        // rather than silently failing every cache write later.
                        if let Err(e) = std::fs::create_dir_all(dir) {
                            errs.push(format!("cache-store dir {dir:?}: {e}"));
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

        // Reject mistyped directives/props inside blocks (typos → errors, not
        // silent no-ops) — the nested-block counterpart to the top-level check.
        validate_unknowns(&doc, &mut errs);

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
        // and `:019550` (same socket, different string) are caught too.
        use std::net::SocketAddr;
        let paddr = |s: &str| s.parse::<SocketAddr>().ok();
        for (i, l) in listeners.iter().enumerate() {
            let a = paddr(&l.addr);
            if a.is_some() && listeners[..i].iter().any(|p| paddr(&p.addr) == a) {
                errs.push(format!("duplicate listener address `{}`", l.addr));
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
                Some(ma) if listeners.iter().any(|l| paddr(&l.addr) == Some(ma)) => {
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

        if errs.is_empty() {
            Ok(Config {
                server,
                client_ip_header,
                trusted_proxies,
                geoip,
                listeners,
                alias_prefix,
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

    /// Resolve a request Host to a canonical site host. The migration alias
    /// `<prefix>-<sub>` maps to `<sub>` ONLY when `<sub>` is a configured site —
    /// otherwise the host is returned unchanged, so a genuinely separate
    /// `staging-foo` host is never silently hijacked.
    pub fn canonical(&self, host: &str) -> String {
        if let Some(prefix) = &self.alias_prefix {
            if let Some(rest) = host.strip_prefix(&format!("{prefix}-")) {
                if self.index.contains_key(rest) {
                    return rest.to_string();
                }
            }
        }
        host.to_string()
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
        if prop_str(tls, "cert").is_some() || prop_str(tls, "cert-dir").is_some() {
            return Err(format!(
                "listener {addr:?}: `tls acme=true` can't be combined with cert/cert-dir"
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
        if let Err(e) = crate::certs::CertStore::from_dir(dir) {
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
            if !Path::new(&root).is_dir() {
                return Err(format!(
                    "site `{host}`: file-server root not a directory: {root}"
                ));
            }
            let index = child_arg(f, "index").unwrap_or("index.html").to_string();
            Ok(Handler::File { root, index })
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

fn parse_site(node: &KdlNode) -> Result<Site, String> {
    let host = first_arg(node)
        .ok_or("site needs a host, e.g. site \"app.example.com\"")?
        .to_string();

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

    let deny = parse_deny(node, &host)?;
    let waf = parse_waf(node, &host)?;
    let acme = child_bool(node, "acme").unwrap_or(false);
    let hsts = child_arg(node, "hsts").map(str::to_owned);
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
    fn size_parsing() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("32MiB").unwrap(), 32 * 1024 * 1024);
        assert_eq!(parse_size("10GB").unwrap(), 10_000_000_000);
        assert_eq!(parse_size("512KB").unwrap(), 512_000);
        assert!(parse_size("nope").is_err());
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

//! KDL config: parse `sluice.kdl` into a validated `Config`.
//!
//! Reads like nginx (brace blocks, directives), whitespace-insensitive, with
//! `line:col`-precise diagnostics from the `kdl` crate. `Config::parse` does
//! syntax + semantic validation; `sluice --check` and the (future) hot-reload
//! path both go through it, so a bad edit never reaches a running proxy.

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
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32",
        "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
        "2a06:98c0::/29", "2c0f:f248::/32",
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
    Tls { cert: String, key: String, http2: bool },
    /// SNI-based certs loaded from a directory (`<host>.crt`/`<host>.key`),
    /// served via Pingora's TLS callback and hot-swappable.
    TlsDynamic { cert_dir: String, http2: bool },
    /// Certs auto-provisioned via ACME (needs a top-level `acme {}` block).
    TlsAcme { http2: bool },
    RedirectHttps,
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
    node.children()?.nodes().iter().find(|n| n.name().value() == name)
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
    let v: u64 = num.trim().parse().map_err(|_| format!("invalid size {s:?}"))?;
    v.checked_mul(mult).ok_or_else(|| format!("size {s:?} overflows u64"))
}

fn open_mmdb(path: &str, label: &str, errs: &mut Vec<String>) -> Option<maxminddb::Reader<Vec<u8>>> {
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
            Some(p) => p.parse::<u16>().map_err(|_| format!("upstream {s:?}: bad port {p:?}"))?,
            None if after.is_empty() && default_port != 0 => default_port,
            None if after.is_empty() => {
                return Err(format!("upstream {s:?}: IPv6 literal needs a :port"))
            }
            None => return Err(format!("upstream {s:?}: junk after IPv6 address: {after:?}")),
        };
        (addr.to_string(), port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>().map_err(|_| format!("upstream {s:?}: bad port {p:?}"))?,
            ),
            None if default_port != 0 => (hostport.to_string(), default_port),
            None => return Err(format!("upstream {s:?} must be host:port or a http(s):// URL")),
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

/// Stable (run-independent) hash for Ketama ring points and key lookup.
fn stable_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// Build a Ketama consistent-hash ring: each backend gets `160 * weight` points,
/// so its share of the key space is proportional to its weight and removing one
/// backend only reshuffles that backend's arcs.
fn build_ketama_ring(servers: &[Upstream]) -> Vec<(u64, usize)> {
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

const TOP_LEVEL: &[&str] = &[
    "server",
    "client-ip",
    "geoip",
    "acme",
    "listener",
    "alias",
    "defaults",
    "site",
];

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {path}: {e}"))?;
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
        let mut geoip = None;
        let mut listeners = Vec::new();
        let mut alias_prefix = None;
        let mut acme: Option<AcmeCfg> = None;
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
                        server.threads = v.max(0) as usize;
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
                        for a in all_args(tp) {
                            match a.parse::<IpNet>() {
                                Ok(net) => trusted_proxies.push(net),
                                Err(_) => errs.push(format!("client-ip trusted-proxies: bad CIDR {a:?}")),
                            }
                        }
                    }
                }
                "geoip" => {
                    let enabled = child_bool(node, "enabled").unwrap_or(true);
                    if enabled {
                        let country_header = child_arg(node, "country-header")
                            .map(|s| s.to_ascii_lowercase());
                        let log_fields = child(node, "log-fields")
                            .map(all_args)
                            .unwrap_or_default();
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
                        let asn_reader =
                            child_arg(node, "mmdb-asn").and_then(|p| open_mmdb(p, "mmdb-asn", &mut errs));
                        let city_reader =
                            child_arg(node, "mmdb-city").and_then(|p| open_mmdb(p, "mmdb-city", &mut errs));
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
                "alias" => {
                    alias_prefix = prop_str(node, "prefix").map(str::to_owned);
                }
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
                "defaults" => {
                    if let Some(v) = child_arg(node, "hsts") {
                        default_hsts = Some(v.to_string());
                    }
                    if let Some(v) = child_int(node, "unknown-host") {
                        match u16::try_from(v) {
                            Ok(c) if (100..=599).contains(&c) => unknown_host = c,
                            _ => errs.push(format!("defaults unknown-host: {v} is not a valid HTTP status")),
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
        let has_acme_listener = listeners
            .iter()
            .any(|l| matches!(l.kind, ListenerKind::TlsAcme { .. }));
        if acme.is_none() && has_acme_listener {
            errs.push("a listener uses `tls acme=true` but there is no `acme {}` block".to_string());
        }
        // HTTP-01 challenges are answered on the :80 redirect listener; without one
        // ACME can never validate.
        if has_acme_listener
            && !listeners.iter().any(|l| matches!(l.kind, ListenerKind::RedirectHttps))
        {
            errs.push(
                "`tls acme=true` needs a `listener \"0.0.0.0:80\" { redirect-to-https true }` \
                 to answer HTTP-01 challenges"
                    .to_string(),
            );
        }
        // ACME is opt-in per site (`acme true`). Tie the flag to the machinery.
        let any_acme_site = sites.iter().any(|s| s.acme);
        if any_acme_site && acme.is_none() {
            errs.push("a site sets `acme true` but there is no `acme {}` block".to_string());
        }
        if any_acme_site && !has_acme_listener {
            errs.push(
                "a site sets `acme true` but no listener uses `tls acme=true`".to_string(),
            );
        }
        if sites.is_empty() {
            errs.push("no `site` defined".to_string());
        }

        if trusted_proxies.is_empty() {
            trusted_proxies = CF_RANGES.clone();
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
        return Ok(Listener { addr, kind: ListenerKind::RedirectHttps });
    }
    let tls = child(node, "tls")
        .ok_or_else(|| format!("listener {addr:?}: needs a `tls` block or `redirect-to-https true`"))?;
    let http2 = child_bool(node, "http2").unwrap_or(false);

    // ACME-managed certs (needs a top-level `acme {}` block).
    if prop_bool(tls, "acme").unwrap_or(false) {
        return Ok(Listener { addr, kind: ListenerKind::TlsAcme { http2 } });
    }
    // Dynamic SNI certs from a directory, or a single cert/key pair.
    if let Some(dir) = prop_str(tls, "cert-dir") {
        if !Path::new(dir).is_dir() {
            return Err(format!("listener {addr:?}: cert-dir not a directory: {dir}"));
        }
        return Ok(Listener {
            addr,
            kind: ListenerKind::TlsDynamic { cert_dir: dir.to_string(), http2 },
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
    Ok(Listener { addr, kind: ListenerKind::Tls { cert, key, http2 } })
}

/// Collect `deny "<regex>"` children into compiled regexes.
fn parse_deny(node: &KdlNode, host: &str) -> Result<Vec<Regex>, String> {
    let mut deny = Vec::new();
    if let Some(children) = node.children() {
        for d in children.nodes().iter().filter(|n| n.name().value() == "deny") {
            let pat = first_arg(d).ok_or_else(|| format!("site `{host}`: deny needs a path regex"))?;
            deny.push(Regex::new(pat).map_err(|e| format!("site `{host}`: deny regex {pat:?}: {e}"))?);
        }
    }
    Ok(deny)
}

fn parse_max_body(node: &KdlNode, host: &str) -> Result<Option<u64>, String> {
    match child_arg(node, "max-body") {
        Some(s) => Ok(Some(parse_size(s).map_err(|e| format!("site `{host}`: {e}"))?)),
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
            Ok(Some(CacheCfg { ttl: Duration::from_secs(ttl), max_object }))
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
        for s in children.nodes().iter().filter(|n| n.name().value() == "server") {
            let a = first_arg(s)
                .ok_or_else(|| format!("site `{host}`: upstream server needs an address"))?;
            let mut u = parse_upstream(a).map_err(|e| format!("site `{host}`: {e}"))?;
            if let Some(w) = prop_int(s, "weight") {
                if w < 1 {
                    return Err(format!("site `{host}`: server {a:?} weight must be ≥ 1"));
                }
                u.weight = w.min(u32::MAX as i128) as u32;
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
    Ok(UpstreamGroup { servers, balance, health_check, ring })
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
    Ok(HealthCheck { path, interval, timeout, healthy, unhealthy, expect_status })
}

/// The backend of a site or location: exactly one of `upstream` / `file-server`.
fn parse_handler(node: &KdlNode, host: &str) -> Result<Handler, String> {
    match (child(node, "upstream"), child(node, "file-server")) {
        (Some(_), Some(_)) => {
            Err(format!("site `{host}`: set either upstream or file-server, not both"))
        }
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
                return Err(format!("site `{host}`: file-server root not a directory: {root}"));
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
        for f in children.nodes().iter().filter(|n| n.name().value() == "sub-filter") {
            let from = prop_str(f, "from")
                .ok_or_else(|| format!("site `{host}`: sub-filter needs from=\"...\""))?;
            if from.is_empty() {
                return Err(format!("site `{host}`: sub-filter from must be non-empty"));
            }
            let to = prop_str(f, "to").unwrap_or("");
            fs.push(SubFilter { from: from.as_bytes().to_vec(), to: to.as_bytes().to_vec() });
        }
    }
    let max = fs.iter().map(|f| f.from.len()).max().unwrap_or(0);
    Ok((fs, max))
}

/// A `location "<matcher>" { ... }` block. `~` prefix on the matcher = regex,
/// otherwise a path prefix.
fn parse_location(node: &KdlNode, host: &str) -> Result<Location, String> {
    let m = first_arg(node)
        .ok_or_else(|| format!("site `{host}`: location needs a path matcher"))?;
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
    let Some(w) = child(node, "waf") else { return Ok(rules) };
    let Some(children) = w.children() else { return Ok(rules) };
    for b in children.nodes().iter().filter(|n| n.name().value() == "block") {
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
        let re =
            Regex::new(pat).map_err(|e| format!("site `{host}`: waf regex {pat:?}: {e}"))?;
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
        for l in children.nodes().iter().filter(|n| n.name().value() == "location") {
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
            let rps = prop_int(r, "rps").unwrap_or(0) as f64;
            let burst = prop_int(r, "burst").map(|b| b as f64).unwrap_or(rps);
            if rps <= 0.0 {
                return Err(format!("site `{host}`: rate-limit needs rps > 0"));
            }
            Some(RateLimit { rps, burst: burst.max(rps) })
        }
        None => None,
    };

    let mut redirects = Vec::new();
    if let Some(children) = node.children() {
        for r in children.nodes().iter().filter(|n| n.name().value() == "redirect") {
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
                .ok_or_else(|| format!("site `{host}`: redirect status {raw_status} not in 300..=399"))?;
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

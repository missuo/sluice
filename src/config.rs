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
}

pub struct Site {
    pub host: String,
    /// Proxy backend. None for a file-server site.
    pub upstream: Option<Upstream>,
    /// Static file root. None for a proxy site. Exactly one of upstream/file_root is set.
    pub file_root: Option<String>,
    pub index: String,
    /// Paths matching any of these regexes get 403 (nginx `deny`).
    pub deny: Vec<Regex>,
    pub websocket: bool,
    pub max_body: Option<u64>,
    pub read_timeout: Option<Duration>,
    pub hsts: Option<String>,
    pub cloudflare_only: bool,
    pub rate_limit: Option<RateLimit>,
    pub redirects: Vec<Redirect>,
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
    })
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

fn parse_site(node: &KdlNode) -> Result<Site, String> {
    let host = first_arg(node)
        .ok_or("site needs a host, e.g. site \"app.example.com\"")?
        .to_string();

    // Backend: exactly one of `upstream` (proxy) or `file-server` (static).
    let upstream = match child_arg(node, "upstream") {
        Some(u) => {
            let mut up = parse_upstream(u).map_err(|e| format!("site `{host}`: {e}"))?;
            if let Some(h) = child_arg(node, "upstream-host") {
                up.host_header = Some(h.to_string());
            }
            if let Some(v) = child_bool(node, "upstream-verify") {
                up.verify = v;
            }
            Some(up)
        }
        None => None,
    };
    let (file_root, index) = match child(node, "file-server") {
        Some(fs) => {
            let root = child_arg(fs, "root")
                .ok_or_else(|| format!("site `{host}`: file-server missing root"))?
                .to_string();
            if !Path::new(&root).is_dir() {
                return Err(format!("site `{host}`: file-server root not a directory: {root}"));
            }
            let index = child_arg(fs, "index").unwrap_or("index.html").to_string();
            (Some(root), index)
        }
        None => (None, "index.html".to_string()),
    };
    match (&upstream, &file_root) {
        (Some(_), Some(_)) => return Err(format!("site `{host}`: set either upstream or file-server, not both")),
        (None, None) => return Err(format!("site `{host}`: needs an upstream or a file-server")),
        _ => {}
    }

    let mut deny = Vec::new();
    if let Some(children) = node.children() {
        for d in children.nodes().iter().filter(|n| n.name().value() == "deny") {
            let pat = first_arg(d).ok_or_else(|| format!("site `{host}`: deny needs a path regex"))?;
            deny.push(Regex::new(pat).map_err(|e| format!("site `{host}`: deny regex {pat:?}: {e}"))?);
        }
    }

    let websocket = child_bool(node, "websocket").unwrap_or(false);
    let max_body = match child_arg(node, "max-body") {
        Some(s) => Some(parse_size(s).map_err(|e| format!("site `{host}`: {e}"))?),
        None => None,
    };
    let read_timeout = child_int(node, "read-timeout-secs").map(|v| Duration::from_secs(v.max(0) as u64));
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
        upstream,
        file_root,
        index,
        deny,
        websocket,
        max_body,
        read_timeout,
        hsts,
        cloudflare_only,
        rate_limit,
        redirects,
    })
}

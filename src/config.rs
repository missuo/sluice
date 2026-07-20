//! KDL config: parse `sluice.kdl` into a validated `Config`.
//!
//! Reads like nginx (brace blocks, directives), whitespace-insensitive, with
//! `line:col`-precise diagnostics from the `kdl` crate. `Config::parse` does
//! syntax + semantic validation; `sluice --check` and the (future) hot-reload
//! path both go through it, so a bad edit never reaches a running proxy.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use kdl::{KdlDocument, KdlError, KdlNode};
use regex::Regex;

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
    pub geoip: Option<GeoipCfg>,
    pub listeners: Vec<Listener>,
    pub alias_prefix: Option<String>,
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
    RedirectHttps,
}

#[derive(Debug)]
pub struct Site {
    pub host: String,
    pub upstream_host: String,
    pub upstream_port: u16,
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
    num.trim()
        .parse::<u64>()
        .map(|v| v * mult)
        .map_err(|_| format!("invalid size {s:?}"))
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

fn split_hostport(s: &str) -> Result<(String, u16), String> {
    let (h, p) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("upstream {s:?} must be host:port"))?;
    let port = p
        .parse::<u16>()
        .map_err(|_| format!("upstream {s:?}: bad port {p:?}"))?;
    Ok((h.to_string(), port))
}

const TOP_LEVEL: &[&str] = &[
    "server",
    "client-ip",
    "geoip",
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
        let mut geoip = None;
        let mut listeners = Vec::new();
        let mut alias_prefix = None;
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
                "defaults" => {
                    if let Some(v) = child_arg(node, "hsts") {
                        default_hsts = Some(v.to_string());
                    }
                    if let Some(v) = child_int(node, "unknown-host") {
                        unknown_host = v as u16;
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
        if sites.is_empty() {
            errs.push("no `site` defined".to_string());
        }

        if errs.is_empty() {
            Ok(Config {
                server,
                client_ip_header,
                geoip,
                listeners,
                alias_prefix,
                unknown_host,
                sites,
                index,
            })
        } else {
            Err(errs.join("\n"))
        }
    }

    /// Resolve a request Host to a canonical site host, reporting if it arrived
    /// on the migration test alias (so apex redirects can stay on the alias).
    pub fn canonical<'a>(&self, host: &'a str) -> (String, bool) {
        if let Some(prefix) = &self.alias_prefix {
            if host == format!("{prefix}.{}", self.apex_suffix()) {
                // bare alias apex -> apex (best-effort; requires a site named apex)
            }
            if let Some(rest) = host.strip_prefix(&format!("{prefix}-")) {
                return (rest.to_string(), true);
            }
        }
        (host.to_string(), false)
    }

    fn apex_suffix(&self) -> &str {
        // not strictly needed for MVP; alias is `<prefix>-<sub>` form.
        ""
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
    let cert = prop_str(tls, "cert")
        .ok_or_else(|| format!("listener {addr:?}: tls missing cert"))?
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
    let http2 = child_bool(node, "http2").unwrap_or(false);
    Ok(Listener { addr, kind: ListenerKind::Tls { cert, key, http2 } })
}

fn parse_site(node: &KdlNode) -> Result<Site, String> {
    let host = first_arg(node)
        .ok_or("site needs a host, e.g. site \"app.example.com\"")?
        .to_string();
    let upstream = child_arg(node, "upstream")
        .ok_or_else(|| format!("site `{host}`: missing upstream"))?;
    let (upstream_host, upstream_port) = split_hostport(upstream)?;

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
            let status = prop_int(r, "status").unwrap_or(301) as u16;
            if !(300..=399).contains(&status) {
                return Err(format!("site `{host}`: redirect status {status} not in 300..=399"));
            }
            redirects.push(Redirect { re, target, status });
        }
    }

    Ok(Site {
        host,
        upstream_host,
        upstream_port,
        websocket,
        max_body,
        read_timeout,
        hsts,
        cloudflare_only,
        rate_limit,
        redirects,
    })
}

//! sluice — a config-driven edge proxy on Pingora.
//!
//!   sluice -c /etc/sluice/sluice.kdl        # run
//!   sluice --check -c sluice.kdl            # validate config and exit

use std::sync::Arc;

use arc_swap::ArcSwap;
use pingora::listeners::tls::TlsSettings;
use pingora::proxy::http_proxy_service;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::Server;
use pingora::services::listening::Service as ListeningService;

use sluice::config::{Config, ListenerKind};
use sluice::proxy::{RedirectProxy, SluiceProxy};
use sluice::{acme, certs};

const DEFAULT_CONFIG: &str = "/etc/sluice/sluice.kdl";

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse our own args (kept separate from Pingora's Opt).
    let mut config_path = DEFAULT_CONFIG.to_string();
    let mut check = false;
    let mut upgrade = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-c" | "--config" => {
                config_path = it.next().unwrap_or_else(|| fatal("-c needs a path"));
            }
            "--check" => check = true,
            // Zero-downtime binary upgrade: start the new process with -u; it
            // acquires the listening sockets from the running one over the
            // upgrade socket, then SIGQUIT the old process to drain and exit.
            "-u" | "--upgrade" => upgrade = true,
            "-h" | "--help" => {
                println!("sluice [-c <config.kdl>] [--check] [-u|--upgrade]");
                return;
            }
            other => fatal(&format!("unknown argument: {other}")),
        }
    }

    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error in {config_path}:\n{e}");
            std::process::exit(1);
        }
    };

    if check {
        println!(
            "{config_path}: ok — {} site(s), {} listener(s){}",
            config.sites.len(),
            config.listeners.len(),
            if config.geoip.is_some() {
                ", geoip on"
            } else {
                ""
            }
        );
        return;
    }

    // Server config from the file.
    let threads = if config.server.threads > 0 {
        config.server.threads
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    };
    let mut conf = ServerConf {
        threads,
        grace_period_seconds: Some(config.server.grace_period_secs),
        graceful_shutdown_timeout_seconds: Some(config.server.graceful_shutdown_secs),
        upstream_keepalive_pool_size: config.server.upstream_keepalive_pool,
        ..Default::default()
    };
    if let Some(sock) = &config.server.upgrade_sock {
        conf.upgrade_sock = sock.clone();
    } else if upgrade {
        // The FD handoff passes the listening sockets over this Unix socket. The
        // Pingora default lives in world-writable /tmp; on a shared host a local
        // user could squat it and hijack the sockets. Recommend a private path.
        log::warn!(
            "sluice: --upgrade with no `server.upgrade-sock` set; using the default in /tmp. \
             Set upgrade-sock to a path in a 0700 dir (e.g. /run/sluice via systemd RuntimeDirectory)."
        );
    }

    // `upgrade` makes bootstrap acquire the listening FDs from the old process
    // (via `upgrade-sock`) instead of binding fresh — zero-downtime upgrade.
    let opt = Opt {
        upgrade,
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(opt, conf);
    server.bootstrap();
    let threads = server.configuration.threads;

    // Clone what we need to build listeners, then move Config into the ArcSwap.
    let listeners = config.listeners.clone();
    let metrics_addr = config.server.metrics_addr.clone();
    let acme_cfg = config.acme.clone();
    // Only provision hosts that opted in with `acme true` — a CF-fronted host
    // can't pass HTTP-01, so enrolling every site would fail forever.
    let acme_domains: Vec<String> = config
        .sites
        .iter()
        .filter(|s| s.acme)
        .map(|s| s.host.clone())
        .collect();
    if config
        .listeners
        .iter()
        .any(|l| matches!(l.kind, ListenerKind::TlsAcme { .. }))
        && acme_domains.is_empty()
    {
        log::warn!("sluice: a listener uses `tls acme=true` but no site sets `acme true` — no certs will be provisioned");
    }
    let cfg = Arc::new(ArcSwap::from_pointee(config));

    // ACME auto-TLS: a shared cert store (served by SNI) + a challenge map
    // (served on :80). The ACME thread fills both.
    let mut acme_certs: Option<Arc<ArcSwap<certs::CertStore>>> = None;
    let mut acme_challenges: Option<acme::ChallengeStore> = None;
    if let Some(acfg) = acme_cfg {
        let cs = Arc::new(ArcSwap::from_pointee(certs::CertStore::default()));
        let chs: acme::ChallengeStore =
            Arc::new(ArcSwap::from_pointee(std::collections::HashMap::new()));
        acme::spawn(acfg, acme_domains, cs.clone(), chs.clone());
        acme_certs = Some(cs);
        acme_challenges = Some(chs);
    }

    // SIGHUP → hot reload (fail-safe: a bad edit keeps the old config).
    spawn_reload(cfg.clone(), config_path.clone());

    let mut proxy = http_proxy_service(&server.configuration, SluiceProxy::new(cfg.clone()));
    let mut redirector = http_proxy_service(
        &server.configuration,
        RedirectProxy {
            cfg: cfg.clone(),
            challenges: acme_challenges.clone(),
        },
    );
    let mut n_tls = 0;
    let mut n_redirect = 0;

    for l in &listeners {
        match &l.kind {
            ListenerKind::Tls { cert, key, http2 } => {
                let mut tls = TlsSettings::intermediate(cert, key).unwrap_or_else(|e| {
                    fatal(&format!("TLS for {}: cert {cert} / key {key}: {e}", l.addr))
                });
                if *http2 {
                    tls.enable_h2();
                }
                proxy.add_tls_with_settings(&l.addr, None, tls);
                n_tls += 1;
            }
            ListenerKind::TlsDynamic { cert_dir, http2 } => {
                let store = certs::CertStore::from_dir(cert_dir)
                    .unwrap_or_else(|e| fatal(&format!("cert-dir {cert_dir}: {e}")));
                let store = Arc::new(ArcSwap::from_pointee(store));
                let mut tls = TlsSettings::with_callbacks(Box::new(certs::DynamicCert { store }))
                    .unwrap_or_else(|e| fatal(&format!("dynamic TLS for {}: {e}", l.addr)));
                if *http2 {
                    tls.enable_h2();
                }
                proxy.add_tls_with_settings(&l.addr, None, tls);
                n_tls += 1;
            }
            ListenerKind::TlsAcme { http2 } => {
                let store = acme_certs
                    .clone()
                    .unwrap_or_else(|| fatal("listener tls acme=true but no `acme {}` block"));
                let mut tls = TlsSettings::with_callbacks(Box::new(certs::DynamicCert { store }))
                    .unwrap_or_else(|e| fatal(&format!("acme TLS for {}: {e}", l.addr)));
                if *http2 {
                    tls.enable_h2();
                }
                proxy.add_tls_with_settings(&l.addr, None, tls);
                n_tls += 1;
            }
            ListenerKind::RedirectHttps => {
                redirector.add_tcp(&l.addr);
                n_redirect += 1;
            }
        }
    }

    log::info!(
        "sluice: {n_tls} tls + {n_redirect} redirect listener(s), {threads} worker thread(s)"
    );
    if n_tls > 0 {
        server.add_service(proxy);
    }
    if n_redirect > 0 {
        server.add_service(redirector);
    }
    if let Some(m) = &metrics_addr {
        let mut metrics = ListeningService::prometheus_http_service();
        metrics.add_tcp(m);
        log::info!("sluice: metrics at {m}");
        server.add_service(metrics);
    }

    server.run_forever();
}

fn fatal(msg: &str) -> ! {
    eprintln!("sluice: {msg}");
    std::process::exit(2);
}

/// Reload the config on SIGHUP. On parse/validation failure the running config
/// is kept untouched, so a bad edit never takes the proxy down.
fn spawn_reload(cfg: Arc<ArcSwap<Config>>, path: String) {
    use signal_hook::consts::SIGHUP;
    use signal_hook::iterator::Signals;
    std::thread::spawn(move || {
        let mut signals = match Signals::new([SIGHUP]) {
            Ok(s) => s,
            Err(e) => {
                log::error!("cannot install SIGHUP handler: {e}");
                return;
            }
        };
        for _ in signals.forever() {
            match Config::load(&path) {
                Ok(new) => {
                    let n = new.sites.len();
                    cfg.store(Arc::new(new));
                    log::info!("SIGHUP: reloaded {path} ({n} site(s))");
                }
                Err(e) => log::error!("SIGHUP: reload FAILED, keeping old config:\n{e}"),
            }
        }
    });
}

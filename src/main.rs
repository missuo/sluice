//! sluice — a config-driven edge proxy on Pingora.
//!
//!   sluice -c /etc/sluice/sluice.kdl        # run
//!   sluice --check -c sluice.kdl            # validate config and exit

mod certs;
mod config;
mod metrics;
mod proxy;

use std::sync::Arc;

use arc_swap::ArcSwap;
use pingora::listeners::tls::TlsSettings;
use pingora::proxy::http_proxy_service;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::Server;
use pingora::services::listening::Service as ListeningService;

use config::{Config, ListenerKind};
use proxy::{RedirectProxy, SluiceProxy};

const DEFAULT_CONFIG: &str = "/etc/sluice/sluice.kdl";

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse our own args (kept separate from Pingora's Opt).
    let mut config_path = DEFAULT_CONFIG.to_string();
    let mut check = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-c" | "--config" => {
                config_path = it.next().unwrap_or_else(|| fatal("-c needs a path"));
            }
            "--check" => check = true,
            "-h" | "--help" => {
                println!("sluice [-c <config.kdl>] [--check]");
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
            if config.geoip.is_some() { ", geoip on" } else { "" }
        );
        return;
    }

    // Server config from the file.
    let mut conf = ServerConf::default();
    conf.threads = if config.server.threads > 0 {
        config.server.threads
    } else {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    };
    conf.grace_period_seconds = Some(config.server.grace_period_secs);
    conf.graceful_shutdown_timeout_seconds = Some(config.server.graceful_shutdown_secs);
    conf.upstream_keepalive_pool_size = config.server.upstream_keepalive_pool;
    if let Some(sock) = &config.server.upgrade_sock {
        conf.upgrade_sock = sock.clone();
    }

    let mut server = Server::new_with_opt_and_conf(None::<Opt>, conf);
    server.bootstrap();
    let threads = server.configuration.threads;

    // Clone what we need to build listeners, then move Config into the ArcSwap.
    let listeners = config.listeners.clone();
    let metrics_addr = config.server.metrics_addr.clone();
    let cfg = Arc::new(ArcSwap::from_pointee(config));

    // SIGHUP → hot reload (fail-safe: a bad edit keeps the old config).
    spawn_reload(cfg.clone(), config_path.clone());

    let mut proxy = http_proxy_service(&server.configuration, SluiceProxy::new(cfg));
    let mut redirector = http_proxy_service(&server.configuration, RedirectProxy);
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
            ListenerKind::RedirectHttps => {
                redirector.add_tcp(&l.addr);
                n_redirect += 1;
            }
        }
    }

    log::info!("sluice: {n_tls} tls + {n_redirect} redirect listener(s), {threads} worker thread(s)");
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

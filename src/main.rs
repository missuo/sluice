//! sluice — a config-driven edge proxy on Pingora.
//!
//!   sluice -c /etc/sluice/sluice.kdl        # run
//!   sluice --check -c sluice.kdl            # validate config and exit

use std::sync::Arc;

use arc_swap::ArcSwap;
use pingora::listeners::tls::TlsSettings;
use pingora::proxy::http_proxy;
use pingora::server::configuration::{Opt, ServerConf};
use pingora::server::Server;
use pingora::services::listening::Service;

use sluice::config::{Config, ListenerKind};
use sluice::proxy::{AcceptFilter, ConnCapApp, ConnLimiter, RedirectProxy, SluiceProxy};
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
        // Validate the upgrade-socket policy under --check too, so a bad
        // `-u`/`upgrade-sock` combination is caught before deploy.
        if let Err(e) = validate_upgrade_sock(&config, upgrade) {
            eprintln!("sluice: {e}");
            std::process::exit(1);
        }
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

    // Privilege separation: refuse to serve as root. A memory-safety or
    // file-handling flaw anywhere in the TLS/proxy/cache/ACME path would be a
    // full host compromise if we keep UID 0. The supported deployment runs as a
    // dedicated `sluice` user with only CAP_NET_BIND_SERVICE (see the shipped
    // systemd unit, examples/sluice.service). An explicit escape hatch exists for
    // environments that truly need it.
    enforce_privilege_separation(&config);

    // Zero-downtime upgrade uses a Unix socket to hand the listening FDs to the
    // new process. Pingora's default lives in world-writable /tmp with a 0666
    // mode and no peer authentication, so a local user could squat it and hijack
    // the sockets. Require a service-owned 0700 directory before allowing `-u`.
    if let Err(e) = validate_upgrade_sock(&config, upgrade) {
        fatal(&e);
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
        // Drop to this user/group after binding when Pingora daemonizes. The
        // primary supported path is the systemd unit's `User=`/`Group=`, but
        // honoring these lets a daemonized run drop privileges too.
        user: config.server.run_user.clone(),
        group: config.server.run_group.clone(),
        ..Default::default()
    };
    if let Some(sock) = &config.server.upgrade_sock {
        conf.upgrade_sock = sock.clone();
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
    let max_conn_per_ip = config.server.max_conn_per_ip;
    let tls_handshake_timeout_secs = config.server.tls_handshake_timeout_secs.max(1);
    let h2_idle_timeout_secs = config.server.h2_idle_timeout_secs;
    let h2_handshake_timeout_secs = config.server.h2_handshake_timeout_secs;
    let graceful_shutdown_secs = config.server.graceful_shutdown_secs;
    let metrics_addr = config.server.metrics_addr.clone();
    let acme_cfg = config.acme.clone();
    let disk_cfg = config.disk_cache.clone();
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

    // Provision the disk cache dir NOW (fatal on error — a misconfigured
    // `cache-store` dir must fail startup, not silently fall back to memory and
    // hide the misconfiguration). The fd-pinned root is shared with the reaper.
    let disk_root: Option<Arc<sluice::dirs::SecureDir>> = disk_cfg.map(|dc| {
        let root = Arc::new(
            sluice::dirs::SecureDir::provision(&dc.dir)
                .unwrap_or_else(|e| fatal(&format!("cache-store dir: {e}"))),
        );
        sluice::diskcache::spawn_reaper(root.clone(), dc.max_size, dc.max_files, dc.min_free);
        log::info!("sluice: response cache = disk ({})", dc.dir);
        root
    });

    // ACME auto-TLS: a shared cert store (served by SNI) + a challenge map
    // (served on :80). Provisioning + cached-cert load happen synchronously
    // (fatal on error) BEFORE the listeners bind, so `:443` never comes up with
    // an empty cert store.
    let mut acme_certs: Option<Arc<ArcSwap<certs::CertStore>>> = None;
    let mut acme_challenges: Option<acme::ChallengeStore> = None;
    if let Some(acfg) = acme_cfg {
        let cs = Arc::new(ArcSwap::from_pointee(certs::CertStore::default()));
        let chs: acme::ChallengeStore =
            Arc::new(ArcSwap::from_pointee(std::collections::HashMap::new()));
        acme::spawn(acfg, acme_domains, cs.clone(), chs.clone()).unwrap_or_else(|e| fatal(&e));
        acme_certs = Some(cs);
        acme_challenges = Some(chs);
    }

    // Registry of hot-reloadable cert-dir stores (populated while building the TLS
    // listeners below), so SIGHUP can atomically re-read rotated certs. The SIGHUP
    // handler is installed AFTER the listeners are built so it has this registry.
    let mut cert_dir_registry: Vec<CertDirStore> = Vec::new();

    // One shared per-IP in-flight connection limiter across BOTH public listeners
    // (TLS proxy + :80 redirect/ACME), so a client's connections to either are
    // counted together against `max-conn-per-ip`. It is enforced at two stages:
    //  - `AcceptFilter` (a ConnectionFilter) rejects an over-cap source right
    //    after TCP accept, BEFORE the TLS handshake — the only pre-handshake hook
    //    Pingora exposes, and our defense against a partial-ClientHello flood; and
    //  - `ConnCapApp` holds an exact per-connection guard across `process_new` for
    //    the connection's whole life, released on close.
    // (max 0 = disabled, a no-op fast path everywhere.)
    // Pending-slot TTL is derived from the configurable TLS-handshake timeout, but
    // strictly LONGER (handshake timeout + a scheduling/cleanup grace) so the
    // pre-handshake per-IP accounting can never expire before the vendored accept
    // loop's handshake deadline — which starts only after the accepted connection's
    // task is scheduled (see ConnLimiter::for_handshake_timeout).
    let conn_limiter = Arc::new(ConnLimiter::for_handshake_timeout(
        max_conn_per_ip,
        std::time::Duration::from_secs(tls_handshake_timeout_secs),
    ));
    if max_conn_per_ip > 0 {
        log::info!("sluice: max {max_conn_per_ip} in-flight connection(s) per client IP");
        // Reclaim expired pending slots even when the source IP never returns
        // (abandoned pre-handshake sockets have no close callback).
        conn_limiter.spawn_sweeper();
    }

    let mut proxy_inner = http_proxy(
        &server.configuration,
        SluiceProxy::new(cfg.clone(), disk_root),
    );
    // Bound idle downstream HTTP/2 connections: stock Pingora waits on the next
    // stream forever, so a client that completes the H2 handshake and then stays
    // silent pins the socket/TLS/H2 state/FD indefinitely. This closes a
    // connection idle (no active streams) for `h2-idle-timeout-secs`; a
    // long-running active stream keeps it open. 0 = disabled. Enforced by the
    // vendored h2 accept-loop patch (vendor/pingora-core/PATCH.md, Patch 6).
    let mut server_opts = pingora::apps::HttpServerOptions::default();
    if h2_idle_timeout_secs > 0 {
        server_opts.h2_idle_timeout = Some(std::time::Duration::from_secs(h2_idle_timeout_secs));
    }
    // Bound the graceful-shutdown H2 drain by the global graceful deadline: on
    // SIGQUIT/upgrade drain the accept loop keeps dispatching already-sent streams
    // (so queued requests aren't lost and the final GOAWAY carries the true
    // last-stream-id for safe retry), then force-closes at this deadline so an
    // uncooperative peer can't hang the drain (PATCH.md, Patch 6).
    if graceful_shutdown_secs > 0 {
        server_opts.h2_graceful_shutdown_timeout =
            Some(std::time::Duration::from_secs(graceful_shutdown_secs));
    }
    // Bound the H2 connection-preface handshake: stock Pingora awaits the client's
    // 24-byte preface with no deadline and the idle timeout only starts afterwards,
    // so a client that negotiates ALPN h2 then sends no/partial preface pins the
    // connection indefinitely. Kept FINITE (min 1s) even if the idle timeout is off
    // (PATCH.md, Patch 6).
    server_opts.h2_handshake_timeout = Some(std::time::Duration::from_secs(
        h2_handshake_timeout_secs.max(1),
    ));
    proxy_inner.server_options = Some(server_opts);
    let proxy_app = ConnCapApp::new(proxy_inner, conn_limiter.clone());
    let mut proxy = Service::new("Pingora HTTP Proxy Service".to_string(), proxy_app);
    let redirect_app = ConnCapApp::new(
        http_proxy(
            &server.configuration,
            RedirectProxy {
                cfg: cfg.clone(),
                challenges: acme_challenges.clone(),
            },
        ),
        conn_limiter.clone(),
    );
    let mut redirector = Service::new("Sluice :80 redirect".to_string(), redirect_app);
    // Bound the downstream (TLS) handshake with a finite, short deadline (vendored
    // Patch 7): a partial ClientHello otherwise retains a socket/task for the whole
    // window before any Sluice code runs (pre-HTTP Slowloris on direct exposure).
    // Applied to BOTH the TLS proxy and the :80 redirect service.
    let hs_timeout = std::time::Duration::from_secs(tls_handshake_timeout_secs);
    proxy.set_handshake_timeout(hs_timeout);
    redirector.set_handshake_timeout(hs_timeout);
    // Install the pre-handshake accept filter on both services (no-op when the cap
    // is disabled, so it's cheap to always attach).
    if conn_limiter.enabled() {
        proxy.set_connection_filter(Arc::new(AcceptFilter::new(conn_limiter.clone())));
        redirector.set_connection_filter(Arc::new(AcceptFilter::new(conn_limiter.clone())));
    }
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
                let store = certs::CertStore::from_dir_strict(cert_dir)
                    .unwrap_or_else(|e| fatal(&format!("cert-dir {cert_dir}: {e}")));
                let store = Arc::new(ArcSwap::from_pointee(store));
                // Retain a handle so SIGHUP can re-read this dir's rotated certs.
                cert_dir_registry.push(CertDirStore {
                    cert_dir: cert_dir.clone(),
                    store: store.clone(),
                });
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

    // SIGHUP → hot reload (fail-safe: a bad edit keeps the old config; a bad cert
    // replacement or a listener-topology change keeps the old config AND certs).
    // Installed now that the cert-dir registry is populated.
    spawn_reload(cfg.clone(), config_path.clone(), cert_dir_registry);

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
        let mut metrics = Service::prometheus_http_service();
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

/// Refuse to keep running as root unless explicitly allowed. Running the full
/// TLS/proxy/cache/ACME surface as UID 0 turns any memory-safety or
/// file-handling flaw into a host compromise. The escape hatch is a config
/// `server { allow-root true }` or `SLUICE_ALLOW_ROOT=1`, for environments that
/// genuinely cannot use the shipped systemd unit's dedicated user + ambient
/// CAP_NET_BIND_SERVICE.
fn enforce_privilege_separation(config: &Config) {
    // SAFETY: geteuid() is always safe; it only reads the effective UID.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return;
    }
    let allow_env = std::env::var("SLUICE_ALLOW_ROOT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    // If a user/group is configured AND we will daemonize, Pingora drops
    // privileges after binding, so root at startup is acceptable in that case.
    // We are not daemonizing here (systemd runs us in the foreground), so a
    // configured user/group alone does not drop privileges — require the
    // explicit allow.
    if config.server.allow_root || allow_env {
        log::warn!(
            "sluice: running as root (allow-root set). This is discouraged — prefer the systemd \
             unit with a dedicated user and AmbientCapabilities=CAP_NET_BIND_SERVICE."
        );
        return;
    }
    fatal(
        "refusing to run as root (uid 0). Run under the shipped systemd unit \
         (examples/sluice.service) as a dedicated `sluice` user with \
         AmbientCapabilities=CAP_NET_BIND_SERVICE, or set `server { allow-root true }` / \
         SLUICE_ALLOW_ROOT=1 to override.",
    );
}

/// Zero-downtime upgrade (`-u`) hands the listening file descriptors to the new
/// process over a Unix socket. Pingora creates that socket mode 0666 and later
/// `unlink`s/`bind`s it by PATH, and it does not authenticate the peer, so the
/// path must resolve to a location no other (non-root) user can influence —
/// otherwise a local user could rename an ancestor after our check (a
/// path-based TOCTOU), substitute a directory they control, and steal the
/// listening FDs or inject descriptors.
///
/// We enforce that with an fd-anchored `openat`/`fstat` walk from `/`: every
/// ancestor directory above the socket's own directory must be root-owned and
/// not group/other-writable (so no non-root user can rename any component), and
/// the socket's directory itself must be owned by root or the service and be
/// mode 0700. On a standard system `/run/sluice` (a systemd `RuntimeDirectory`)
/// satisfies this. This closes the rename TOCTOU for every non-root attacker
/// (root is already trusted); a configured path outside such a hierarchy is
/// rejected rather than trusted.
fn validate_upgrade_sock(config: &Config, upgrade: bool) -> Result<(), String> {
    validate_upgrade_sock_path(config.server.upgrade_sock.as_deref(), upgrade)
}

fn validate_upgrade_sock_path(sock: Option<&str>, upgrade: bool) -> Result<(), String> {
    // The policy only matters when we actually perform an upgrade handoff.
    if !upgrade {
        return Ok(());
    }
    let Some(sock) = sock else {
        return Err(
            "`-u`/`--upgrade` requires `server { upgrade-sock \"...\" }` set to a path inside a \
             root-owned, non-writable hierarchy with a service-owned 0700 leaf (e.g. \
             /run/sluice/upgrade.sock via systemd RuntimeDirectory). Refusing the world-writable \
             /tmp default."
                .to_string(),
        );
    };
    if !sock.starts_with('/') {
        return Err(format!(
            "server upgrade-sock {sock:?}: must be an absolute path (e.g. /run/sluice/upgrade.sock)"
        ));
    }
    let (parent, leaf) = sock.rsplit_once('/').unwrap_or(("", sock));
    if leaf.is_empty() {
        return Err(format!(
            "server upgrade-sock {sock:?}: must name a socket file, not a directory"
        ));
    }
    if parent.is_empty() {
        return Err(format!(
            "server upgrade-sock {sock:?}: refusing a socket directly under `/`; use a \
             service-owned 0700 directory (e.g. /run/sluice)"
        ));
    }
    // Validate the socket filename itself. Pingora later feeds the raw path to
    // `UnixAddr::new(...).unwrap()` / `bind(...).unwrap()`, so a `.`/`..`/NUL leaf
    // or an over-length path would panic the real upgrade even though `--check -u`
    // "passed" — reject them here so the check matches runtime.
    if leaf == "." || leaf == ".." {
        return Err(format!(
            "server upgrade-sock {sock:?}: {leaf:?} is not a valid socket filename"
        ));
    }
    if sock.contains('\0') {
        return Err(format!(
            "server upgrade-sock {sock:?}: path must not contain a NUL byte"
        ));
    }
    // The bound path (plus its NUL terminator) must fit the platform's
    // `sockaddr_un.sun_path` (108 on Linux, 104 on macOS); otherwise bind() fails.
    let sun_path_max = {
        let un: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        un.sun_path.len()
    };
    if sock.len() >= sun_path_max {
        return Err(format!(
            "server upgrade-sock {sock:?}: path is {} bytes, exceeding the platform \
             Unix-socket limit of {} bytes",
            sock.len(),
            sun_path_max - 1
        ));
    }
    validate_socket_dir(parent).map_err(|e| format!("server upgrade-sock {sock:?}: {e}"))
}

/// One-directory owner/mode policy for the upgrade-socket path. Split out from
/// the syscall walk so it can be unit-tested directly. `is_ancestor` = a
/// directory strictly above the socket's own directory.
fn check_dir_meta(
    uid: u32,
    mode: u32,
    is_ancestor: bool,
    euid: u32,
    name: &str,
) -> Result<(), String> {
    if is_ancestor {
        // Any non-root owner, or any group/other write bit, means a local user
        // could rename this component after the check and redirect the later
        // path-based bind — the TOCTOU the no-symlink check alone can't close.
        if uid != 0 {
            return Err(format!(
                "ancestor {name:?} is owned by uid {uid}, not root; a non-root owner could rename \
                 it to redirect the socket (TOCTOU). Put the socket under a root-owned hierarchy \
                 such as /run."
            ));
        }
        if mode & 0o022 != 0 {
            return Err(format!(
                "ancestor {name:?} is group/other-writable (mode {:04o}); a local user could \
                 rename it (TOCTOU). Put the socket under a root-owned, non-writable hierarchy \
                 such as /run.",
                mode & 0o7777
            ));
        }
    } else {
        // The socket's own directory holds the 0666 handoff socket; it must be
        // owned by root or us and be 0700 so no other user can enter it.
        if uid != 0 && uid != euid {
            return Err(format!(
                "socket directory {name:?} is owned by uid {uid}, not root or the service (uid \
                 {euid})"
            ));
        }
        if mode & 0o077 != 0 {
            return Err(format!(
                "socket directory {name:?} must be 0700 (mode {:04o} exposes it to group/other)",
                mode & 0o7777
            ));
        }
        // The owner must have write AND execute (search) on the directory, or the
        // later `bind()` cannot create the socket in it — e.g. a service-owned
        // 0500/0400 dir passes the "no group/other" test yet the upgrade then
        // fails at runtime. Requiring owner `wx` (with the group/other check above
        // this is effectively 0700, allowing 0300) makes `--check -u` agree with
        // what bind actually needs.
        if mode & 0o300 != 0o300 {
            return Err(format!(
                "socket directory {name:?} lacks owner write+execute (mode {:04o}); bind would \
                 fail — it must be 0700 (owner rwx)",
                mode & 0o7777
            ));
        }
    }
    Ok(())
}

/// fd-anchored `openat`/`fstat` walk of the socket's directory path from `/`,
/// applying [`check_dir_meta`] to every component. Refuses symlink components
/// (`O_NOFOLLOW`) so the check can't be pointed elsewhere, and validates the
/// REAL inode at each step rather than re-resolving a string.
fn validate_socket_dir(dir: &str) -> Result<(), String> {
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    // `st.st_mode` is `u16` on macOS (mode_t) but `u32` on Linux, so `as u32`
    // is a real widening on macOS yet a same-type (redundant) cast on Linux,
    // where clippy's `unnecessary_cast` fires under `-D warnings`. Allow it here
    // rather than diverge the code per platform.
    #[allow(clippy::unnecessary_cast)]
    fn fstat_dir(fd: RawFd) -> Result<(u32, u32), String> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(format!("fstat: {}", std::io::Error::last_os_error()));
        }
        if (st.st_mode as u32) & (libc::S_IFMT as u32) != (libc::S_IFDIR as u32) {
            return Err("not a directory".to_string());
        }
        Ok((st.st_uid, st.st_mode as u32))
    }

    let euid = unsafe { libc::geteuid() };
    let comps: Vec<&str> = dir.split('/').filter(|c| !c.is_empty()).collect();
    if comps.is_empty() {
        return Err("must be a directory below `/`".to_string());
    }
    if comps.iter().any(|c| *c == "." || *c == "..") {
        return Err("must not contain `.` or `..` components".to_string());
    }

    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    // Anchor at "/" and validate it as an ancestor.
    let root_fd = unsafe { libc::open(c"/".as_ptr(), flags) };
    if root_fd < 0 {
        return Err(format!(
            "cannot open `/`: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut cur = unsafe { OwnedFd::from_raw_fd(root_fd) };
    let (uid, mode) = fstat_dir(cur.as_raw_fd())?;
    check_dir_meta(uid, mode, true, euid, "/")?;

    for (i, comp) in comps.iter().enumerate() {
        let is_leaf = i == comps.len() - 1;
        let cstr = std::ffi::CString::new(*comp)
            .map_err(|_| format!("component {comp:?} contains a NUL byte"))?;
        let fd = unsafe { libc::openat(cur.as_raw_fd(), cstr.as_ptr(), flags) };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            // The service-owned RuntimeDirectory may not exist yet at `--check`
            // time; systemd creates it 0700 at start. Every ancestor above it has
            // already been validated as root-owned + non-writable, so an attacker
            // cannot pre-create the leaf here.
            if is_leaf && e.raw_os_error() == Some(libc::ENOENT) {
                return Ok(());
            }
            // ELOOP / ENOTDIR here means a symlink or non-directory component.
            return Err(format!("component {comp:?}: {e}"));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let (uid, mode) = fstat_dir(fd.as_raw_fd())?;
        check_dir_meta(uid, mode, !is_leaf, euid, comp)?;
        cur = fd;
    }
    Ok(())
}

/// A hot-reloadable `cert-dir` store: the directory path plus the live `ArcSwap`
/// that the TLS callback reads. On SIGHUP the directory is re-read and the store
/// atomically swapped, so a rotated cert is served without a restart.
struct CertDirStore {
    cert_dir: String,
    store: Arc<ArcSwap<certs::CertStore>>,
}

/// Server settings that are baked into the process at STARTUP (into the pingora
/// `ServerConf`, the per-`Service` handshake timeout, the `ConnLimiter`, the H2
/// `HttpServerOptions`, the DNS-cache semaphore, or the metrics service) and are
/// NOT re-read per request. A SIGHUP that changes any of them would silently have
/// no effect, so the reload is rejected rather than giving false assurance that a
/// tightened security window (e.g. `tls-handshake-timeout-secs`) took effect.
///
/// Fields read per request (e.g. `downstream-*-timeout-secs`, `request-timeout-secs`,
/// `min-send-rate-bytes`, `upstream-dns-{timeout,ttl,stale}-secs`) are deliberately
/// NOT here — those DO take effect on reload.
fn changed_startup_settings(old: &Config, new: &Config) -> Vec<&'static str> {
    let (o, n) = (&old.server, &new.server);
    let mut changed = Vec::new();
    macro_rules! chk {
        ($field:ident, $name:literal) => {
            if o.$field != n.$field {
                changed.push($name);
            }
        };
    }
    chk!(threads, "threads");
    chk!(metrics_addr, "metrics-addr");
    chk!(grace_period_secs, "grace-period-secs");
    chk!(graceful_shutdown_secs, "graceful-shutdown-secs");
    chk!(upstream_keepalive_pool, "upstream-keepalive-pool");
    chk!(upgrade_sock, "upgrade-sock");
    chk!(allow_root, "allow-root");
    chk!(run_user, "user");
    chk!(run_group, "group");
    chk!(max_conn_per_ip, "max-conn-per-ip");
    chk!(tls_handshake_timeout_secs, "tls-handshake-timeout-secs");
    chk!(h2_idle_timeout_secs, "h2-idle-timeout-secs");
    chk!(h2_handshake_timeout_secs, "h2-handshake-timeout-secs");
    chk!(upstream_dns_max_concurrent, "upstream-dns-max-concurrent");

    // Startup-bound state that lives OUTSIDE `ServerCfg`. Each is baked into a
    // live worker at startup and cannot be moved by a SIGHUP, so a change must be
    // rejected rather than logged as a successful no-op (false assurance):
    //   * `disk_cache` provisions the on-disk storage + eviction reaper (backend,
    //     dir, and size/file/free limits) once at startup.
    //   * the top-level `acme` block (contact / staging / cache dir) configures the
    //     background ACME worker once at startup.
    //   * the SET of `acme`-enabled site hosts is captured into that worker's
    //     domain list at startup — newly-enabled hosts would silently get no cert.
    if old.disk_cache != new.disk_cache {
        changed.push("disk-cache");
    }
    if old.acme != new.acme {
        changed.push("acme");
    }
    if acme_host_set(old) != acme_host_set(new) {
        changed.push("acme-hosts");
    }
    changed
}

/// The normalized SET of `acme`-enabled site hosts (lowercased, deduped, order-
/// independent) — what the startup ACME worker provisions. Compared across a
/// reload so enabling/disabling `acme` on a site, which the running worker can't
/// pick up, is rejected instead of silently ignored.
fn acme_host_set(cfg: &Config) -> std::collections::BTreeSet<String> {
    cfg.sites
        .iter()
        .filter(|s| s.acme)
        .map(|s| s.host.to_ascii_lowercase())
        .collect()
}

/// Apply a SIGHUP reload, or leave EVERYTHING (config + certs) untouched.
///
/// Steps, any failure of which returns `Err` with the OLD config + certs still in
/// force (fail-before-commit):
///   1. Reject if the listener topology / TLS source paths changed — listeners are
///      startup-only.
///   2. Reject if any STARTUP-ONLY server setting changed (see
///      [`changed_startup_settings`]) — swapping it would not affect the live
///      services/limiter and would give false assurance.
///   3. Load every replacement `cert-dir` store STRICTLY and COMPLETELY up front,
///      so a partially-rotated / malformed / empty replacement never leaves a stale
///      or wrong store live.
///   4. Only once all loads succeed, swap every store and then the config.
///
/// ATOMICITY: each individual `ArcSwap` swap is atomic — a TLS callback always sees
/// a complete OLD or NEW cert store, and a request always sees a complete OLD or NEW
/// config — and NOTHING is committed if any step above fails. This is NOT a single
/// global publication boundary, however: the cert stores and the config are separate
/// `ArcSwap`s swapped in sequence, so during a successful reload a caller could
/// momentarily observe a new store with the old config (or two dynamic listeners at
/// different generations). That window is memory-safe (each callback retains its
/// loaded `Arc`) and benign for SNI-keyed cert stores, which are selected
/// independently per handshake; global cross-store/config atomicity is intentionally
/// not provided.
fn apply_reload(
    cfg: &Arc<ArcSwap<Config>>,
    new: Config,
    registry: &[CertDirStore],
) -> Result<(usize, usize), String> {
    let current = cfg.load();
    if new.listeners != current.listeners {
        return Err(
            "listener topology or TLS source paths changed (listeners are \
                    startup-only); a restart is required — keeping the old config + certs"
                .to_string(),
        );
    }
    let changed = changed_startup_settings(&current, &new);
    if !changed.is_empty() {
        return Err(format!(
            "startup-only server setting(s) changed ({}); these take effect only on \
             restart — keeping the old config + certs",
            changed.join(", ")
        ));
    }
    // Load ALL replacements strictly before swapping ANY (fail-before-commit).
    let mut loaded: Vec<(&Arc<ArcSwap<certs::CertStore>>, certs::CertStore)> = Vec::new();
    for entry in registry {
        match certs::CertStore::from_dir_strict(&entry.cert_dir) {
            Ok(store) => loaded.push((&entry.store, store)),
            Err(e) => {
                return Err(format!(
                    "cert-dir {:?} failed to reload ({e}) — keeping the old config + certs",
                    entry.cert_dir
                ));
            }
        }
    }
    // All loads succeeded: swap every cert store (each swap atomic), then the config.
    let n_stores = loaded.len();
    for (store, new_store) in loaded {
        store.store(Arc::new(new_store));
    }
    let n_sites = new.sites.len();
    cfg.store(Arc::new(new));
    Ok((n_sites, n_stores))
}

/// Reload the config + cert-dir stores on SIGHUP. On ANY failure (parse, listener
/// topology change, or a bad cert-dir replacement) the running config AND certs are
/// kept untouched, so a bad edit or half-rotated cert never takes the proxy down.
fn spawn_reload(cfg: Arc<ArcSwap<Config>>, path: String, registry: Vec<CertDirStore>) {
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
                Ok(new) => match apply_reload(&cfg, new, &registry) {
                    Ok((n_sites, n_stores)) => log::info!(
                        "SIGHUP: reloaded {path} ({n_sites} site(s), {n_stores} cert-dir store(s))"
                    ),
                    Err(e) => log::error!("SIGHUP: reload REJECTED: {e}"),
                },
                Err(e) => log::error!("SIGHUP: reload FAILED, keeping old config:\n{e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_dir_meta_ancestor_policy() {
        let euid = 1000;
        // Root-owned, not group/other-writable → OK ancestor.
        assert!(check_dir_meta(0, 0o755, true, euid, "/run").is_ok());
        assert!(check_dir_meta(0, 0o711, true, euid, "/run").is_ok());
        // A non-root-owned ancestor is the TOCTOU hole (attacker can rename it).
        assert!(check_dir_meta(1000, 0o755, true, euid, "/home/alice").is_err());
        // A group/other-writable ancestor (e.g. /tmp at 1777) is rejected.
        assert!(check_dir_meta(0, 0o1777, true, euid, "/tmp").is_err());
        assert!(check_dir_meta(0, 0o775, true, euid, "/x").is_err()); // group-writable
    }

    #[test]
    fn check_dir_meta_leaf_policy() {
        let euid = 1000;
        // Service-owned 0700 leaf → OK; root-owned 0700 also OK; 0300 (owner wx,
        // no read) is also bindable and private → OK.
        assert!(check_dir_meta(1000, 0o700, false, euid, "/run/sluice").is_ok());
        assert!(check_dir_meta(0, 0o700, false, euid, "/run/sluice").is_ok());
        assert!(check_dir_meta(1000, 0o300, false, euid, "/run/sluice").is_ok());
        // Any group/other bit on the leaf exposes the 0666 handoff socket.
        assert!(check_dir_meta(1000, 0o750, false, euid, "/run/sluice").is_err());
        assert!(check_dir_meta(1000, 0o701, false, euid, "/run/sluice").is_err());
        // Owned by some other unprivileged user → rejected.
        assert!(check_dir_meta(1234, 0o700, false, euid, "/run/sluice").is_err());
        // Owner lacks write (0500) or execute (0600) → bind would fail → rejected.
        assert!(check_dir_meta(1000, 0o500, false, euid, "/run/sluice").is_err());
        assert!(check_dir_meta(1000, 0o400, false, euid, "/run/sluice").is_err());
        assert!(check_dir_meta(1000, 0o600, false, euid, "/run/sluice").is_err());
    }

    #[test]
    fn validate_socket_dir_rejects_world_writable_and_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let base = std::env::temp_dir().join(format!("sluice-usock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let base = std::fs::canonicalize(&base).unwrap();

        // A world-writable ancestor under our temp tree is rejected (the temp
        // root itself is typically user-owned, which also trips the root-owned
        // ancestor rule — either way this must NOT validate).
        let ww = base.join("wide");
        std::fs::create_dir(&ww).unwrap();
        std::fs::set_permissions(&ww, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(validate_socket_dir(ww.to_str().unwrap()).is_err());

        // A symlink component is refused (O_NOFOLLOW).
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.join("link");
        symlink(&real, &link).unwrap();
        assert!(validate_socket_dir(link.to_str().unwrap()).is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn validate_upgrade_sock_requires_safe_path_when_upgrading() {
        // No upgrade-sock + `-u` → error; without `-u` → ok regardless.
        assert!(validate_upgrade_sock_path(None, false).is_ok());
        assert!(validate_upgrade_sock_path(None, true).is_err());
        // A relative path is rejected.
        assert!(validate_upgrade_sock_path(Some("run/sluice/up.sock"), true).is_err());
        // A socket directly under `/` is rejected.
        assert!(validate_upgrade_sock_path(Some("/up.sock"), true).is_err());
        // The world-writable /tmp default is rejected (ancestor not root-owned /
        // is group+other writable, or is a symlink on macOS).
        assert!(validate_upgrade_sock_path(Some("/tmp/pingora_upgrade.sock"), true).is_err());
    }

    #[test]
    fn validate_upgrade_sock_rejects_bad_leaf_and_overlong_path() {
        // `.`/`..` socket filenames (Pingora would `UnixAddr::new(...).unwrap()`
        // on them) are rejected before the fs walk.
        assert!(validate_upgrade_sock_path(Some("/run/sluice/."), true).is_err());
        assert!(validate_upgrade_sock_path(Some("/run/sluice/.."), true).is_err());
        // A path longer than the platform sun_path limit is rejected (would panic
        // bind at runtime) rather than falsely passing `--check -u`.
        let sun_path_max = {
            let un: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            un.sun_path.len()
        };
        let overlong = format!("/run/sluice/{}", "a".repeat(sun_path_max));
        assert!(validate_upgrade_sock_path(Some(&overlong), true).is_err());
    }

    // ---- cert-dir hot-reload (SIGHUP) tests ----

    /// A unique temp directory under the system temp dir.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        // A monotonic-ish unique suffix without external crates.
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!(
            "sluice-reload-{tag}-{n}-{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Write a self-signed `<host>.crt` + `<host>.key` pair into `dir`.
    fn write_self_signed(dir: &std::path::Path, host: &str) {
        let ck = rcgen::generate_simple_self_signed(vec![host.to_string()]).unwrap();
        std::fs::write(dir.join(format!("{host}.crt")), ck.cert.pem()).unwrap();
        std::fs::write(dir.join(format!("{host}.key")), ck.key_pair.serialize_pem()).unwrap();
    }

    /// Build a config string with ONE cert-dir listener at `addr` + `n_sites` sites.
    fn cfg_text(addr: &str, cert_dir: &std::path::Path, n_sites: usize) -> String {
        let mut s = format!(
            "listener \"{addr}\" {{\n tls cert-dir=\"{}\"\n}}\n",
            cert_dir.display()
        );
        for i in 0..n_sites {
            s.push_str(&format!(
                "site \"s{i}.test\" {{\n upstream \"127.0.0.1:9001\"\n}}\n"
            ));
        }
        s
    }

    fn store_of(dir: &std::path::Path) -> Arc<ArcSwap<certs::CertStore>> {
        Arc::new(ArcSwap::from_pointee(
            certs::CertStore::from_dir_strict(dir.to_str().unwrap()).unwrap(),
        ))
    }

    #[test]
    fn reload_serves_a_rotated_cert_and_swaps_config() {
        let dir = temp_dir("rotate");
        write_self_signed(&dir, "a.test");
        let cur = Config::parse(&cfg_text("127.0.0.1:8443", &dir, 1)).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(cur));
        let store = store_of(&dir);
        let registry = vec![CertDirStore {
            cert_dir: dir.to_str().unwrap().to_string(),
            store: store.clone(),
        }];
        // Before: only a.test.
        assert!(store.load().has_host("a.test"));
        assert!(!store.load().has_host("b.test"));

        // Rotate: add a second cert to the dir, and grow the config's site set.
        write_self_signed(&dir, "b.test");
        let new = Config::parse(&cfg_text("127.0.0.1:8443", &dir, 2)).unwrap();
        let (n_sites, n_stores) = apply_reload(&cfg, new, &registry).expect("reload ok");
        assert_eq!((n_sites, n_stores), (2, 1));
        // The store was re-read (now has b.test too) and the config was swapped.
        assert!(
            store.load().has_host("b.test"),
            "rotated cert must be served after reload"
        );
        assert_eq!(
            cfg.load().sites.len(),
            2,
            "config must be swapped on a successful reload"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_with_a_malformed_replacement_keeps_the_old_cert() {
        let dir = temp_dir("malformed");
        write_self_signed(&dir, "a.test");
        let cur = Config::parse(&cfg_text("127.0.0.1:8443", &dir, 1)).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(cur));
        let store = store_of(&dir);
        let old_store_ptr = store.load_full();
        let registry = vec![CertDirStore {
            cert_dir: dir.to_str().unwrap().to_string(),
            store: store.clone(),
        }];
        // A new config that PARSED while the dir was valid, then the dir is corrupted
        // before we apply — models a bad rotation racing the reload.
        let new = Config::parse(&cfg_text("127.0.0.1:8443", &dir, 2)).unwrap();
        std::fs::write(
            dir.join("a.test.crt"),
            b"-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(dir.join("a.test.key"), b"not a key").unwrap();

        let err = apply_reload(&cfg, new, &registry).expect_err("reload must be rejected");
        assert!(err.contains("failed to reload"), "{err}");
        // The OLD cert store is still live (same Arc), and the config was NOT swapped.
        assert!(
            Arc::ptr_eq(&old_store_ptr, &store.load_full()),
            "old cert must stay live"
        );
        assert!(store.load().has_host("a.test"));
        assert_eq!(
            cfg.load().sites.len(),
            1,
            "config must not be swapped on a failed reload"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_rejects_a_listener_topology_change_and_keeps_old_config() {
        let dir = temp_dir("topology");
        write_self_signed(&dir, "a.test");
        let cur = Config::parse(&cfg_text("127.0.0.1:8443", &dir, 1)).unwrap();
        let cfg = Arc::new(ArcSwap::from_pointee(cur));
        let store = store_of(&dir);
        let old_store_ptr = store.load_full();
        let registry = vec![CertDirStore {
            cert_dir: dir.to_str().unwrap().to_string(),
            store: store.clone(),
        }];
        // New config changes the listener ADDRESS (topology) — listeners are
        // startup-only, so the whole reload must be rejected.
        let new = Config::parse(&cfg_text("127.0.0.1:8444", &dir, 2)).unwrap();
        let err = apply_reload(&cfg, new, &registry).expect_err("topology change must be rejected");
        assert!(err.contains("topology"), "{err}");
        // Nothing changed: old config + old certs still live.
        assert!(Arc::ptr_eq(&old_store_ptr, &store.load_full()));
        assert_eq!(cfg.load().sites.len(), 1, "old config must be retained");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Finding 1: a PARTIALLY-broken multi-host dir must be rejected, keeping the
    /// complete old store (not replaced by a partial store that drops a host).
    #[test]
    fn reload_rejects_a_partial_multi_host_dir_and_keeps_the_complete_old_store() {
        // Each break mode leaves a.test valid but b.test broken a different way.
        for mode in ["missing-key", "malformed-crt", "mismatched-key"] {
            let dir = temp_dir(&format!("partial-{mode}"));
            write_self_signed(&dir, "a.test");
            write_self_signed(&dir, "b.test");
            let cur = Config::parse(&cfg_text("127.0.0.1:8443", &dir, 1)).unwrap();
            let cfg = Arc::new(ArcSwap::from_pointee(cur));
            let store = store_of(&dir);
            let old_store_ptr = store.load_full();
            // The OLD (complete) store has BOTH hosts.
            assert!(store.load().has_host("a.test") && store.load().has_host("b.test"));
            let registry = vec![CertDirStore {
                cert_dir: dir.to_str().unwrap().to_string(),
                store: store.clone(),
            }];
            // Parse the new config while the dir is still complete, then break b.test.
            let new = Config::parse(&cfg_text("127.0.0.1:8443", &dir, 2)).unwrap();
            match mode {
                "missing-key" => {
                    std::fs::remove_file(dir.join("b.test.key")).unwrap();
                }
                "malformed-crt" => {
                    std::fs::write(dir.join("b.test.crt"), b"not a cert").unwrap();
                }
                "mismatched-key" => {
                    // A valid key, but for a DIFFERENT cert → key/cert mismatch.
                    let other =
                        rcgen::generate_simple_self_signed(vec!["other".to_string()]).unwrap();
                    std::fs::write(dir.join("b.test.key"), other.key_pair.serialize_pem()).unwrap();
                }
                _ => unreachable!(),
            }
            let err = apply_reload(&cfg, new, &registry)
                .expect_err(&format!("mode {mode}: partial dir must be rejected"));
            assert!(err.contains("failed to reload"), "mode {mode}: {err}");
            // The complete OLD store is still live: BOTH hosts, same Arc; config kept.
            assert!(
                Arc::ptr_eq(&old_store_ptr, &store.load_full()),
                "mode {mode}: old store must stay live"
            );
            assert!(
                store.load().has_host("a.test") && store.load().has_host("b.test"),
                "mode {mode}: old complete store (a.test + b.test) must remain — a partial \
                 store would drop b.test and mis-serve its SNI"
            );
            assert_eq!(
                cfg.load().sites.len(),
                1,
                "mode {mode}: config must be retained"
            );
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// Finding 2: a SIGHUP that changes a startup-only server setting (e.g.
    /// `tls-handshake-timeout-secs`) must be REJECTED — those never take effect
    /// without a restart, so accepting the reload gives false assurance.
    #[test]
    fn reload_rejects_a_startup_only_setting_change_and_keeps_old_config() {
        let dir = temp_dir("startup-only");
        write_self_signed(&dir, "a.test");
        let base = cfg_text("127.0.0.1:8443", &dir, 1);
        let cur = Config::parse(&format!(
            "server {{\n tls-handshake-timeout-secs 10\n}}\n{base}"
        ))
        .unwrap();
        assert_eq!(cur.server.tls_handshake_timeout_secs, 10);
        let cfg = Arc::new(ArcSwap::from_pointee(cur));
        let store = store_of(&dir);
        let old_store_ptr = store.load_full();
        let registry = vec![CertDirStore {
            cert_dir: dir.to_str().unwrap().to_string(),
            store: store.clone(),
        }];
        // Change ONLY the startup-only handshake timeout (listeners unchanged).
        let new = Config::parse(&format!(
            "server {{\n tls-handshake-timeout-secs 3\n}}\n{base}"
        ))
        .unwrap();
        let err =
            apply_reload(&cfg, new, &registry).expect_err("startup-only change must be rejected");
        assert!(err.contains("tls-handshake-timeout-secs"), "{err}");
        assert!(err.contains("startup-only"), "{err}");
        // Old config + certs retained (the live 10s window is unchanged).
        assert!(Arc::ptr_eq(&old_store_ptr, &store.load_full()));
        assert_eq!(cfg.load().server.tls_handshake_timeout_secs, 10);

        // Control: changing ONLY a per-request field IS accepted (it reloads).
        let new_ok = Config::parse(&format!(
            "server {{\n tls-handshake-timeout-secs 10\n request-timeout-secs 45\n}}\n{base}"
        ))
        .unwrap();
        apply_reload(&cfg, new_ok, &registry).expect("a per-request setting change must reload");
        assert_eq!(cfg.load().server.request_timeout_secs, 45);

        std::fs::remove_dir_all(&dir).ok();
    }

    // The startup fingerprint must also cover state that lives OUTSIDE `ServerCfg`
    // — the disk cache, the ACME block, and the ACME-enabled host set are all
    // provisioned into live workers at startup, so a SIGHUP that changes one must
    // be REJECTED (retaining old config + stores), not logged as a no-op success.
    // Fields are set directly on an already-parsed config to isolate the
    // fingerprint under test from KDL filesystem validation.

    #[test]
    fn reload_rejects_a_disk_cache_change_and_keeps_old_config() {
        let dir = temp_dir("disk-cache");
        write_self_signed(&dir, "a.test");
        let base = cfg_text("127.0.0.1:8443", &dir, 1);
        let cur = Config::parse(&base).unwrap();
        assert!(cur.disk_cache.is_none());
        let cfg = Arc::new(ArcSwap::from_pointee(cur));
        let store = store_of(&dir);
        let old_store_ptr = store.load_full();
        let registry = vec![CertDirStore {
            cert_dir: dir.to_str().unwrap().to_string(),
            store: store.clone(),
        }];

        // Enable the disk cache — the storage + reaper are startup-bound.
        let mut new = Config::parse(&base).unwrap();
        new.disk_cache = Some(sluice::config::DiskCacheCfg {
            dir: "/var/cache/sluice".into(),
            max_size: 1 << 30,
            max_files: 1000,
            min_free: 1 << 20,
        });
        let err =
            apply_reload(&cfg, new, &registry).expect_err("disk-cache change must be rejected");
        assert!(err.contains("disk-cache"), "{err}");
        assert!(err.contains("startup-only"), "{err}");
        // Old config + certs retained.
        assert!(Arc::ptr_eq(&old_store_ptr, &store.load_full()));
        assert!(
            cfg.load().disk_cache.is_none(),
            "old config (no disk cache) must be retained"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_rejects_an_acme_config_change_and_keeps_old_config() {
        let dir = temp_dir("acme-cfg");
        write_self_signed(&dir, "a.test");
        let base = cfg_text("127.0.0.1:8443", &dir, 1);
        let cur = Config::parse(&base).unwrap();
        assert!(cur.acme.is_none());
        let cfg = Arc::new(ArcSwap::from_pointee(cur));
        let store = store_of(&dir);
        let old_store_ptr = store.load_full();
        let registry = vec![CertDirStore {
            cert_dir: dir.to_str().unwrap().to_string(),
            store: store.clone(),
        }];

        // Add a top-level ACME block — the ACME worker is startup-bound.
        let mut new = Config::parse(&base).unwrap();
        new.acme = Some(sluice::config::AcmeCfg {
            contact: "ops@example.com".into(),
            staging: false,
            cache_dir: "/var/lib/sluice/acme".into(),
        });
        let err =
            apply_reload(&cfg, new, &registry).expect_err("acme config change must be rejected");
        assert!(err.contains("acme"), "{err}");
        assert!(err.contains("startup-only"), "{err}");
        assert!(
            cfg.load().acme.is_none(),
            "old config (no acme) must be retained"
        );
        assert!(Arc::ptr_eq(&old_store_ptr, &store.load_full()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_rejects_an_acme_host_set_change_and_keeps_old_config() {
        let dir = temp_dir("acme-hosts");
        write_self_signed(&dir, "a.test");
        let base = cfg_text("127.0.0.1:8443", &dir, 1);
        let cur = Config::parse(&base).unwrap();
        assert!(!cur.sites[0].acme, "base sites are not ACME-enabled");
        let cfg = Arc::new(ArcSwap::from_pointee(cur));
        let store = store_of(&dir);
        let old_store_ptr = store.load_full();
        let registry = vec![CertDirStore {
            cert_dir: dir.to_str().unwrap().to_string(),
            store: store.clone(),
        }];

        // Newly enable ACME on a site host — the worker's domain list is fixed at
        // startup, so the new host would silently never get a cert.
        let mut new = Config::parse(&base).unwrap();
        new.sites[0].acme = true;
        let err =
            apply_reload(&cfg, new, &registry).expect_err("acme-host-set change must be rejected");
        assert!(err.contains("acme-hosts"), "{err}");
        assert!(err.contains("startup-only"), "{err}");
        assert!(
            !cfg.load().sites[0].acme,
            "old config (no ACME host) must be retained"
        );
        assert!(Arc::ptr_eq(&old_store_ptr, &store.load_full()));

        std::fs::remove_dir_all(&dir).ok();
    }
}

//! Regression test for the configurable downstream TLS handshake timeout
//! (vendored Patch 7 + `tls-handshake-timeout-secs`).
//!
//! Upstream Pingora hardcoded a 60s TLS handshake deadline in the accept loop, so
//! a silent or byte-dripped partial ClientHello could retain a socket/task for a
//! full minute before any app code ran (pre-HTTP Slowloris on direct exposure).
//! Sluice now sets a finite, short deadline via `Service::set_handshake_timeout`.
//!
//! This drives a REAL TLS `Service` (the patched vendored accept loop) with a short
//! handshake timeout and asserts:
//!   * a silent ClientHello is dropped at ~the deadline,
//!   * a byte-dripped partial ClientHello is dropped at the SAME single deadline
//!     (the drip does not reset it), and
//!   * a prompt valid TLS handshake still succeeds.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::apps::ServerApp;
use pingora::listeners::tls::TlsSettings;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use pingora::services::listening::Service;
use pingora::services::Service as ServiceTrait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Trivial app: after a completed handshake, close the connection.
struct EchoApp;

#[async_trait]
impl ServerApp for EchoApp {
    async fn process_new(
        self: &Arc<Self>,
        _io: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        None
    }
}

fn temp_dir() -> std::path::PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("sluice-tls-hs-{n}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_and_dripped_clienthello_dropped_at_deadline_valid_succeeds() {
    // Self-signed cert for the listener.
    let dir = temp_dir();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let crt = dir.join("localhost.crt");
    let key = dir.join("localhost.key");
    std::fs::write(&crt, ck.cert.pem()).unwrap();
    std::fs::write(&key, ck.key_pair.serialize_pem()).unwrap();

    let hs_timeout = Duration::from_millis(600);
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let tls = TlsSettings::intermediate(crt.to_str().unwrap(), key.to_str().unwrap()).unwrap();
    let mut svc = Service::new("test-tls".to_string(), EchoApp);
    svc.add_tls_with_settings(&addr, None, tls);
    svc.set_handshake_timeout(hs_timeout);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        svc.start_service(
            #[cfg(unix)]
            None,
            shutdown_rx,
            1,
        )
        .await;
    });
    // Give the listener a moment to bind.
    tokio::time::sleep(Duration::from_millis(250)).await;

    // --- Phase 1: silent ClientHello (send nothing). The server must close the
    // connection at ~the handshake deadline. ---
    {
        let mut s = TcpStream::connect(&addr).await.expect("connect");
        let start = Instant::now();
        let mut buf = [0u8; 1];
        let r = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await;
        let elapsed = start.elapsed();
        assert!(
            r.is_ok(),
            "silent handshake was NOT closed at the deadline ({elapsed:?})"
        );
        assert!(
            elapsed >= Duration::from_millis(400),
            "silent handshake closed before the deadline ({elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "silent handshake close far exceeded the deadline ({elapsed:?})"
        );
    }

    // --- Phase 2: byte-dripped partial ClientHello. The drip continues PAST the
    // deadline; the single (non-resettable) deadline must still fire at ~600ms. ---
    {
        let s = TcpStream::connect(&addr).await.expect("connect");
        let (mut rd, mut wr) = s.into_split();
        let dripper = tokio::spawn(async move {
            // A TLS record header claiming an 80-byte handshake body, then a trickle
            // that never completes it.
            let _ = wr.write_all(&[0x16, 0x03, 0x01, 0x00, 0x50]).await;
            let _ = wr.flush().await;
            for _ in 0..20 {
                if wr.write_all(&[0x00]).await.is_err() {
                    break;
                }
                let _ = wr.flush().await;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        });
        let start = Instant::now();
        let mut buf = [0u8; 1];
        let r = tokio::time::timeout(Duration::from_secs(3), rd.read(&mut buf)).await;
        let elapsed = start.elapsed();
        dripper.abort();
        assert!(
            r.is_ok(),
            "dripped handshake was NOT closed at the deadline ({elapsed:?})"
        );
        assert!(
            elapsed >= Duration::from_millis(400),
            "dripped handshake closed before the deadline ({elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "dripped handshake deadline was reset by the trickle ({elapsed:?})"
        );
    }

    // --- Phase 3: a prompt valid TLS handshake still succeeds. Uses the same TLS
    // backend as the server (openssl/boringssl) via a blocking client. ---
    {
        let addr2 = addr.clone();
        let ok = tokio::task::spawn_blocking(move || {
            use pingora::tls::ssl::{SslConnector, SslMethod, SslVerifyMode};
            let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
            let mut cfg = connector.configure().unwrap();
            cfg.set_verify(SslVerifyMode::NONE);
            let tcp = std::net::TcpStream::connect(&addr2).unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            cfg.connect("localhost", tcp).is_ok()
        })
        .await
        .unwrap();
        assert!(ok, "a prompt valid TLS handshake must succeed");
    }

    let _ = shutdown_tx.send(true);
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

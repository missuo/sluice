//! Regression tests for the vendored `pingora-core` downstream HTTP/2
//! connection-preface handshake timeout (`vendor/pingora-core/PATCH.md`, Patch 6).
//!
//! Stock Pingora awaited the client's 24-byte H2 connection preface with NO
//! deadline, and the post-handshake idle timeout only arms AFTER the handshake
//! returns. A client that negotiated ALPN `h2` (or, here, h2c) and then sent no
//! preface — or byte-dripped a partial one — pinned the socket / TLS+H2 state /
//! conn-limit guard / task indefinitely (FD-exhaustion DoS). The accept loop now
//! wraps `server::handshake` in a single, non-resettable finite timeout.
//!
//! These drive the REAL patched `ServerApp::process_new` over an in-memory duplex
//! (h2c, so the preface flows over the wire and `server::handshake` waits for it):
//!   * `silent_client_after_alpn_is_dropped_at_handshake_deadline` — never sends a
//!     preface → dropped at ~the deadline.
//!   * `dripped_partial_preface_is_dropped_at_single_deadline` — trickles preface
//!     bytes past the deadline → still dropped at ~the deadline (non-resettable).
//!   * `prompt_valid_preface_handshake_succeeds` — a proper h2 client handshake +
//!     request is served, proving the timeout doesn't harm normal clients.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream, ServerApp};
use pingora::http::ResponseHeader;
use pingora::protocols::http::ServerSession;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use tokio::io::AsyncWriteExt;

/// Minimal h2c app: counts accepted streams and answers each with a 200.
struct TestApp {
    opts: HttpServerOptions,
    handled: Arc<AtomicUsize>,
}

#[async_trait]
impl HttpServerApp for TestApp {
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: ServerSession,
        _shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        self.handled.fetch_add(1, Ordering::SeqCst);
        let resp = ResponseHeader::build(200, None).unwrap();
        let _ = session.write_response_header(Box::new(resp)).await;
        let _ = session.write_response_body(Bytes::new(), true).await;
        None
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        Some(&self.opts)
    }
}

fn app(handshake: Duration) -> (Arc<TestApp>, Arc<AtomicUsize>) {
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    opts.h2_handshake_timeout = Some(handshake);
    // Long idle timeout so ONLY the handshake timeout can end a stuck handshake.
    opts.h2_idle_timeout = Some(Duration::from_secs(30));
    let handled = Arc::new(AtomicUsize::new(0));
    (
        Arc::new(TestApp {
            opts,
            handled: handled.clone(),
        }),
        handled,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_client_after_alpn_is_dropped_at_handshake_deadline() {
    let handshake = Duration::from_millis(500);
    let (app, handled) = app(handshake);
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let start = Instant::now();
    let server = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    // Client stays completely silent (no preface), holding the socket open.
    let result = tokio::time::timeout(Duration::from_secs(5), server).await;
    let elapsed = start.elapsed();
    assert!(
        result.is_ok(),
        "process_new never returned for a silent post-ALPN client — socket/FD leaked ({elapsed:?})"
    );
    assert_eq!(
        handled.load(Ordering::SeqCst),
        0,
        "no stream should have been handled"
    );
    assert!(
        elapsed >= Duration::from_millis(350),
        "handshake dropped before its deadline ({elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "handshake not bounded — dropped too late ({elapsed:?})"
    );
    // Keep the client transport alive until here so the close is server-driven.
    let _ = client_io.write(&[]).await;
    drop(client_io);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dripped_partial_preface_is_dropped_at_single_deadline() {
    let handshake = Duration::from_millis(600);
    let (app, handled) = app(handshake);
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let start = Instant::now();
    let server = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    // Drip the 24-byte client preface one byte at a time, at an interval SMALLER
    // than the deadline (so several bytes arrive before it fires) and continuing
    // PAST the deadline. A per-read/resettable timeout would keep extending; the
    // single absolute handshake deadline must fire regardless of this activity.
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let dripper = tokio::spawn(async move {
        for b in PREFACE.iter() {
            if client_io.write_all(&[*b]).await.is_err() {
                break; // server closed — expected once the deadline fires
            }
            let _ = client_io.flush().await;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        client_io
    });

    let result = tokio::time::timeout(Duration::from_secs(5), server).await;
    let elapsed = start.elapsed();
    assert!(
        result.is_ok(),
        "process_new never returned for a byte-dripping client ({elapsed:?})"
    );
    assert_eq!(
        handled.load(Ordering::SeqCst),
        0,
        "no stream should be handled"
    );
    // Fired at ~the single deadline, NOT extended by the ongoing drip.
    assert!(
        elapsed >= Duration::from_millis(450),
        "dropped before the handshake deadline ({elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_millis(2500),
        "deadline was reset by the byte-drip (not a single non-resettable deadline) ({elapsed:?})"
    );
    dripper.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prompt_valid_preface_handshake_succeeds() {
    let handshake = Duration::from_millis(500);
    let (app, handled) = app(handshake);
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let server = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    // A proper, prompt h2 client handshake + one request.
    let client = tokio::spawn(async move {
        let (send_req, connection) = h2::client::handshake(client_io).await.unwrap();
        let conn_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut ready = send_req.ready().await.unwrap();
        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .body(())
            .unwrap();
        let (resp, _body) = ready.send_request(req, true).unwrap();
        let status = resp.await.unwrap().status();
        conn_task.abort();
        status.as_u16()
    });

    let status = tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .expect("valid h2 client did not finish — handshake wrongly dropped")
        .expect("client task panicked");
    assert_eq!(status, 200, "a promptly-prefaced h2 request must be served");
    assert_eq!(
        handled.load(Ordering::SeqCst),
        1,
        "the stream should have reached the handler exactly once"
    );
    server.abort();
}

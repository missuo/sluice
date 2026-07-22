//! Regression test for the vendored `pingora-core` downstream HTTP/2
//! idle-connection timeout (`vendor/pingora-core/PATCH.md`, Patch 6).
//!
//! Stock Pingora's h2 accept loop (`apps/mod.rs`) waited on the next stream
//! forever (`TODO: add a timeout?`), so a client that completed the H2 handshake
//! and then opened no stream pinned the socket / TLS / H2 state / file descriptor
//! for the connection's whole life — an unauthenticated FD-exhaustion DoS. The
//! patch closes a connection that stays idle (NO active streams) for a
//! configurable timeout, while a long-running ACTIVE stream keeps it open (the
//! accounting is stream-aware, not a blind timer around `from_h2_conn`).
//!
//! These tests drive the REAL patched `ServerApp::process_new` accept loop over
//! an in-memory `tokio::io::duplex` pipe, with the `h2` crate as the client:
//!   * `idle_h2_connection_is_closed_after_timeout` — handshake then silence →
//!     the server closes the connection at ~the idle timeout, no stream handled.
//!   * `active_stream_survives_past_idle_timeout` — one stream held active far
//!     longer than the idle timeout → the connection is preserved for the whole
//!     active period and only closes after the stream finishes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream, ServerApp};
use pingora::protocols::http::ServerSession;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;

/// A minimal HTTP/2 server app. Each accepted stream is counted and then held
/// open for `hold` (modelling an active/long-running stream) before completing —
/// or panics (to exercise the panic-safe active-stream accounting).
struct TestApp {
    opts: HttpServerOptions,
    hold: Duration,
    handled: Arc<AtomicUsize>,
    panic_on_handle: bool,
}

#[async_trait]
impl HttpServerApp for TestApp {
    async fn process_new_http(
        self: &Arc<Self>,
        _session: ServerSession,
        _shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        self.handled.fetch_add(1, Ordering::SeqCst);
        if self.panic_on_handle {
            // The isolated stream task unwinds here; the RAII guard in the accept
            // loop must still release the active-stream slot.
            panic!("intentional handler panic for the panic-safety regression test");
        }
        // Hold the stream active. While this is in flight the accept loop's
        // active-stream counter is non-zero, so the idle timeout must not fire.
        tokio::time::sleep(self.hold).await;
        None
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        Some(&self.opts)
    }
}

/// Run one case: build an h2c app with the given idle timeout, connect a real
/// `h2` client over a duplex, optionally open one request stream, and measure how
/// long the server's `process_new` runs before it closes the connection. Returns
/// `(elapsed, streams_handled)`.
async fn run_case(idle: Duration, hold: Duration, open_stream: bool) -> (Duration, usize) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let mut opts = HttpServerOptions::default();
    opts.h2c = true; // no ALPN over a duplex; drive the h2c preface path
    opts.h2_idle_timeout = Some(idle);
    let handled = Arc::new(AtomicUsize::new(0));
    let app = Arc::new(TestApp {
        opts,
        hold,
        handled: handled.clone(),
        panic_on_handle: false,
    });

    // ShutdownWatch: keep the SENDER alive for the whole test so `shutdown.changed()`
    // never resolves (a dropped sender would look like a shutdown signal).
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let server_stream: Stream = Box::new(server_io);
    let start = Instant::now();
    let server = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    // Client: h2 handshake, then optionally open exactly one stream, then idle
    // (holding the connection open) until the server decides to close.
    let client = tokio::spawn(async move {
        let (send_req, connection) = h2::client::handshake(client_io).await.unwrap();
        // The connection future must be driven for the handshake/frames to flow.
        let conn_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        // `kept` keeps the client's SendRequest half alive for the whole test so
        // the connection is not closed from the client side; `stream` holds the
        // one open request/response so it is not reset early.
        let (kept, stream) = if open_stream {
            let mut ready = send_req.ready().await.unwrap();
            let req = http::Request::builder()
                .method("GET")
                .uri("/")
                .body(())
                .unwrap();
            let (resp, body) = ready.send_request(req, true).unwrap();
            (ready, Some((resp, body)))
        } else {
            (send_req, None)
        };
        // Hold everything open; the server side owns the close decision.
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(stream);
        drop(kept);
        conn_task.abort();
    });

    // Hard cap so a regression that hangs `process_new` fails loudly instead of
    // hanging the suite.
    let result = tokio::time::timeout(Duration::from_secs(10), server).await;
    let elapsed = start.elapsed();
    client.abort();
    assert!(
        result.is_ok(),
        "process_new did not return within 10s (idle timeout never fired?)"
    );
    (elapsed, handled.load(Ordering::SeqCst))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_h2_connection_is_closed_after_timeout() {
    let idle = Duration::from_millis(400);
    let (elapsed, handled) = run_case(idle, Duration::ZERO, false).await;
    // No stream was ever opened.
    assert_eq!(handled, 0, "no stream should have reached the handler");
    // The connection must have been closed at ~the idle timeout: it waited at
    // least most of the timeout (didn't close instantly) and closed well before
    // the 10s hard cap.
    assert!(
        elapsed >= Duration::from_millis(250),
        "closed too early ({elapsed:?}); the idle timeout was not honored as a wait"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "idle connection was not closed promptly ({elapsed:?})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_stream_survives_past_idle_timeout() {
    let idle = Duration::from_millis(400);
    let hold = Duration::from_millis(1500); // active far longer than `idle`
    let (elapsed, handled) = run_case(idle, hold, true).await;
    assert_eq!(handled, 1, "exactly one stream should have been handled");
    // The connection must NOT have been torn down at the idle timeout while the
    // stream was active: it survived for at least the whole active hold, proving
    // the timer is gated on active-stream accounting, not a blind timer.
    assert!(
        elapsed >= hold,
        "active stream was torn down early ({elapsed:?} < hold {hold:?}); \
         the idle timeout must not fire while a stream is active"
    );
    // It still eventually closes (after the stream finished + one idle period).
    assert!(
        elapsed < hold + Duration::from_secs(5),
        "connection did not close after the active stream finished ({elapsed:?})"
    );
}

/// Finding 1: a RAW H2 client that completes the handshake and then ignores
/// GOAWAY (never reads, never closes) must still have its server-side connection
/// dropped at a finite bound — otherwise the FD/socket leaks. The compliant `h2`
/// client used elsewhere masks this by closing on GOAWAY, so this test speaks raw
/// H2 frames and stays silent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_client_ignoring_goaway_is_dropped_at_finite_bound() {
    use tokio::io::AsyncWriteExt;

    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let idle = Duration::from_millis(400);
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    opts.h2_idle_timeout = Some(idle);
    let app = Arc::new(TestApp {
        opts,
        hold: Duration::ZERO,
        handled: Arc::new(AtomicUsize::new(0)),
        panic_on_handle: false,
    });
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let start = Instant::now();
    let server = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    // Send only the client connection preface + one empty SETTINGS frame, enough
    // for the server handshake to complete. Then go SILENT: never read (so GOAWAY
    // is ignored) and never close.
    client_io
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    // SETTINGS frame: length=0, type=0x04, flags=0, stream id=0.
    client_io
        .write_all(&[0, 0, 0, 0x04, 0x00, 0, 0, 0, 0])
        .await
        .unwrap();
    client_io.flush().await.unwrap();

    // The server must drop `process_new` at a finite bound WITHOUT any peer close.
    let result = tokio::time::timeout(Duration::from_secs(8), server).await;
    let elapsed = start.elapsed();
    assert!(
        result.is_ok(),
        "process_new never returned for a GOAWAY-ignoring client — socket/FD leaked ({elapsed:?})"
    );
    assert!(
        elapsed >= Duration::from_millis(250),
        "closed too early ({elapsed:?}); the idle timeout was not honored as a wait"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "connection not dropped promptly after the bounded drain ({elapsed:?})"
    );
    // Keep the raw client transport alive until here so the close is server-driven.
    drop(client_io);
}

/// Finding 2: a panic inside the isolated stream task must not wedge the
/// per-connection active-stream counter. With the RAII guard the slot is released
/// on unwind, so the connection goes idle and closes at the timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panicking_stream_handler_still_lets_connection_go_idle() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let idle = Duration::from_millis(400);
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    opts.h2_idle_timeout = Some(idle);
    let handled = Arc::new(AtomicUsize::new(0));
    let app = Arc::new(TestApp {
        opts,
        hold: Duration::ZERO,
        handled: handled.clone(),
        panic_on_handle: true,
    });
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let start = Instant::now();
    let server = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    // Compliant client opens exactly one stream (whose handler panics), then idles.
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
        let (_resp, _body) = ready.send_request(req, true).unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(ready);
        conn_task.abort();
    });

    let result = tokio::time::timeout(Duration::from_secs(8), server).await;
    let elapsed = start.elapsed();
    client.abort();
    assert!(
        result.is_ok(),
        "process_new never returned — a panicking handler wedged the counter ({elapsed:?})"
    );
    assert_eq!(
        handled.load(Ordering::SeqCst),
        1,
        "the stream should have reached the (panicking) handler once"
    );
    // The panic released the slot via Drop, so the idle timer armed and fired.
    assert!(
        elapsed < Duration::from_secs(5),
        "panic left the active-stream counter non-zero; connection never went idle ({elapsed:?})"
    );
}

/// Finding 3: on graceful shutdown the accept loop must keep dispatching the
/// streams the client already sent (not drop them), and return within a finite
/// bound. Queue many streams, then flip the ShutdownWatch, and assert every
/// stream was handled and `process_new` returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_drains_queued_h2_streams() {
    const N: usize = 50;

    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    // Long idle timeout so it can't interfere; short graceful bound for the test.
    opts.h2_idle_timeout = Some(Duration::from_secs(30));
    opts.h2_graceful_shutdown_timeout = Some(Duration::from_secs(6));
    let handled = Arc::new(AtomicUsize::new(0));
    let app = Arc::new(TestApp {
        opts,
        hold: Duration::from_millis(50),
        handled: handled.clone(),
        panic_on_handle: false,
    });
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let server = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    let client = tokio::spawn(async move {
        let (mut send_req, connection) = h2::client::handshake(client_io).await.unwrap();
        let conn_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        // Queue N streams (headers-only requests) as fast as the connection allows.
        let mut responses = Vec::new();
        for _ in 0..N {
            let mut ready = send_req.ready().await.unwrap();
            let req = http::Request::builder()
                .method("GET")
                .uri("/")
                .body(())
                .unwrap();
            let (resp, _body) = ready.send_request(req, true).unwrap();
            responses.push(resp);
            send_req = ready;
        }
        // Hold everything open so the server owns the close.
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop((send_req, responses));
        conn_task.abort();
    });

    // Let the client transmit the streams, then signal graceful shutdown.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let _ = shutdown_tx.send(true);

    let result = tokio::time::timeout(Duration::from_secs(8), server).await;
    assert!(
        result.is_ok(),
        "process_new did not return within the graceful drain bound"
    );
    // Every queued stream must have been dispatched despite the shutdown — the old
    // code stopped accepting immediately and lost the not-yet-accepted ones.
    assert_eq!(
        handled.load(Ordering::SeqCst),
        N,
        "queued H2 streams were lost on graceful shutdown"
    );
    client.abort();
}

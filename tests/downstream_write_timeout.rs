//! Regression tests for the default downstream WRITE timeout (round-16 finding 3).
//!
//! A client can request a large response and then stop reading (HTTP/1.1) or
//! withhold `WINDOW_UPDATE` (HTTP/2). Without a write bound the response write
//! future stays pending forever, pinning a connection/FD/task with near-zero
//! attacker bandwidth; on H2 the stream stays "active" so the idle-connection
//! timeout deliberately cannot close it. Sluice now applies a per-write timeout to
//! EVERY request on BOTH protocols by default (`set_write_timeout`, honored for H1
//! and — via a vendored patch — H2). These tests exercise that the write actually
//! aborts at a finite bound when the peer stalls.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream, ServerApp};
use pingora::http::ResponseHeader;
use pingora::protocols::http::ServerSession;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;

/// H1: a client that sends a request and then never reads the response. The
/// response write blocks once the socket buffer fills; the per-write timeout must
/// abort it at a finite bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_slow_reader_response_write_times_out() {
    use pingora::protocols::http::v1::server::HttpSession;
    use tokio::io::AsyncWriteExt;

    // Small pipe buffer so a large body cannot be absorbed; the client never reads.
    let (mut client, server) = tokio::io::duplex(8 * 1024);
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    client.flush().await.unwrap();

    let mut sess = HttpSession::new(Box::new(server));
    sess.read_request().await.unwrap();
    sess.set_write_timeout(Some(Duration::from_millis(500)));

    let body_len = 256 * 1024usize;
    let mut resp = ResponseHeader::build(200, None).unwrap();
    resp.insert_header("Content-Length", body_len.to_string())
        .unwrap();
    sess.write_response_header(Box::new(resp)).await.unwrap();

    // Write a body far larger than the pipe buffer; the client never drains it.
    let body = vec![0u8; body_len];
    let start = Instant::now();
    let res = sess.write_body(&body).await;
    let elapsed = start.elapsed();

    assert!(
        res.is_err(),
        "a stalled H1 reader must abort the response write, got {res:?} after {elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(400),
        "write aborted before the timeout ({elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "write timeout did not fire promptly ({elapsed:?})"
    );
    drop(client);
}

/// A minimal H2 app that writes a large response body and records whether the
/// write aborted (timed out).
struct WriterApp {
    opts: HttpServerOptions,
    write_timeout: Duration,
    body_len: usize,
    write_errored: Arc<Mutex<Option<bool>>>,
}

#[async_trait]
impl HttpServerApp for WriterApp {
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: ServerSession,
        _shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        session.set_write_timeout(Some(self.write_timeout));
        let resp = ResponseHeader::build(200, None).unwrap();
        let _ = session.write_response_header(Box::new(resp)).await;
        let body = Bytes::from(vec![0u8; self.body_len]);
        let res = session.write_response_body(body, true).await;
        *self.write_errored.lock().unwrap() = Some(res.is_err());
        None
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        Some(&self.opts)
    }
}

/// H2: a client that opens a stream, receives the response headers, and then
/// withholds `WINDOW_UPDATE` (never reads the body). Once the initial flow-control
/// window is exhausted the server's body write blocks; the per-write timeout must
/// abort it at a finite bound (the idle-conn timeout cannot, because the stream is
/// still active).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_withheld_window_response_write_times_out() {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);

    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    // Long idle timeout so only the WRITE timeout can end this.
    opts.h2_idle_timeout = Some(Duration::from_secs(30));
    let write_errored = Arc::new(Mutex::new(None));
    let app = Arc::new(WriterApp {
        opts,
        write_timeout: Duration::from_millis(500),
        body_len: 256 * 1024, // > the 65535-byte initial window
        write_errored: write_errored.clone(),
    });

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let server = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

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
        let (resp, _send_body) = ready.send_request(req, true).unwrap();
        // Receive the response HEADERS, then never read the body → withhold window.
        let response = resp.await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop((ready, response));
        conn_task.abort();
    });

    // The handler must record a result at a finite bound (the connection itself
    // stays open/idle afterwards, so we poll the recorded outcome rather than
    // waiting for `process_new` to return).
    let start = Instant::now();
    let outcome = loop {
        if let Some(errored) = *write_errored.lock().unwrap() {
            break errored;
        }
        assert!(
            start.elapsed() < Duration::from_secs(6),
            "H2 response write neither completed nor aborted within 6s (write not bounded)"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert!(
        outcome,
        "the H2 body write should have aborted with a write timeout (withheld window)"
    );
    server.abort();
    client.abort();
}

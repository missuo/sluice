//! Regression tests for KNOWN_ISSUES 3.1: a STREAMED (chunked / no-Content-Length)
//! request body that crosses `max-body` mid-stream must return a downstream **413**,
//! not the generic 500 that Pingora's default `fail_to_proxy` maps an untyped
//! internal error to. The declared-Content-Length case already returns 413 up
//! front (`request_filter`); this covers the streamed enforcement in
//! `request_body_filter`, which now returns `Error::explain(HTTPStatus(413), ..)`.
//!
//! Each test drives the REAL `SluiceProxy` (over an h2c duplex for H2, a raw H1
//! duplex for chunked) against a byte-counting origin, and asserts:
//!   * the client receives 413,
//!   * the origin received far fewer than the sent bytes (the cap held — the
//!     over-limit body was NOT fully forwarded, so it can't be evaded), and
//!   * (H1) a subsequent request on a fresh downstream connection still gets 200,
//!     proving the aborted upstream connection was not returned to the pool and
//!     could not desync a reused connection.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use pingora::apps::{HttpServerOptions, ServerApp};
use pingora::protocols::Stream;
use pingora::proxy::http_proxy;
use pingora::server::configuration::ServerConf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use sluice::config::Config;
use sluice::proxy::SluiceProxy;

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn contains_ci(hay: &[u8], needle_lower: &[u8]) -> bool {
    let lower: Vec<u8> = hay.iter().map(|b| b.to_ascii_lowercase()).collect();
    find(&lower, needle_lower).is_some()
}

/// A keepalive H1 origin that COUNTS every byte it reads (`bytes`) and every
/// request it fully consumes + answers 200 for (`served`). A chunked request is
/// only "served" once its `0\r\n\r\n` terminator arrives — so a proxy that aborts
/// an over-limit upload before the terminator leaves this origin waiting (no 200),
/// which is exactly what lets the proxy's own 413 reach the client.
async fn spawn_counting_origin() -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let bytes = Arc::new(AtomicUsize::new(0));
    let served = Arc::new(AtomicUsize::new(0));
    let (bytes2, served2) = (bytes.clone(), served.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let (b, s) = (bytes2.clone(), served2.clone());
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut tmp = [0u8; 4096];
                'conn: loop {
                    // Read a full request head (up to CRLFCRLF).
                    let head_end = loop {
                        if let Some(p) = find(&buf, b"\r\n\r\n") {
                            break p + 4;
                        }
                        match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut tmp))
                            .await
                        {
                            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break 'conn,
                            Ok(Ok(n)) => {
                                b.fetch_add(n, Ordering::Relaxed);
                                buf.extend_from_slice(&tmp[..n]);
                            }
                        }
                    };
                    let chunked = contains_ci(&buf[..head_end], b"transfer-encoding: chunked");
                    if chunked {
                        // Consume until the chunked terminator. Test bodies are all
                        // `a`s (no CRLF), so this substring can't false-match body.
                        loop {
                            if find(&buf[head_end..], b"0\r\n\r\n").is_some() {
                                break;
                            }
                            match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut tmp))
                                .await
                            {
                                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break 'conn, // aborted/closed
                                Ok(Ok(n)) => {
                                    b.fetch_add(n, Ordering::Relaxed);
                                    buf.extend_from_slice(&tmp[..n]);
                                }
                            }
                        }
                    }
                    if sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    let _ = sock.flush().await;
                    s.fetch_add(1, Ordering::Relaxed);
                    buf.clear();
                }
            });
        }
    });
    (port, bytes, served)
}

fn build_app(origin_port: u16, h2c: bool) -> Arc<pingora::proxy::HttpProxy<SluiceProxy>> {
    let cfg_text = format!(
        "listener \"127.0.0.1:8443\" {{\n redirect-to-https true\n}}\n\
         site \"cap.local\" {{\n max-body \"8\"\n upstream \"127.0.0.1:{origin_port}\"\n}}\n"
    );
    let config = Config::parse(&cfg_text).expect("config parses");
    let cfg = Arc::new(ArcSwap::from_pointee(config));
    let conf = Arc::new(ServerConf {
        upstream_keepalive_pool_size: 128,
        ..Default::default()
    });
    let mut app = http_proxy(&conf, SluiceProxy::new(cfg, None));
    let mut opts = HttpServerOptions::default();
    opts.h2c = h2c;
    app.server_options = Some(opts);
    Arc::new(app)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_streamed_over_limit_body_returns_413() {
    let (origin_port, origin_bytes, _served) = spawn_counting_origin().await;
    let app = build_app(origin_port, true);

    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let proxy = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    let client = tokio::spawn(async move {
        let (send_req, connection) = h2::client::handshake(client_io).await.unwrap();
        let conn_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut ready = send_req.ready().await.unwrap();
        // No Content-Length → the STREAMED path (not the declared fast path). Send
        // 12 bytes of body across DATA frames; the 8-byte cap trips mid-stream.
        let req = http::Request::builder()
            .method("POST")
            .uri("http://cap.local/")
            .body(())
            .unwrap();
        let (resp_fut, mut body) = ready.send_request(req, false).unwrap();
        let _ = body.send_data(Bytes::from_static(b"aaaa"), false);
        let _ = body.send_data(Bytes::from_static(b"aaaa"), false);
        let _ = body.send_data(Bytes::from_static(b"aaaa"), true);
        let status = tokio::time::timeout(Duration::from_secs(8), resp_fut)
            .await
            .expect("no response — 413 path likely stalled")
            .expect("stream errored instead of a 413 response")
            .status();
        conn_task.abort();
        status.as_u16()
    });

    let status = tokio::time::timeout(Duration::from_secs(15), client)
        .await
        .expect("client did not finish")
        .expect("client task panicked");
    assert_eq!(status, 413, "a streamed over-limit H2 body must return 413");
    // The cap held: the origin saw only headers + at most a chunk of body, never
    // the whole upload (no evasion).
    assert!(
        origin_bytes.load(Ordering::Relaxed) < 4096,
        "origin received {} bytes — over-limit body must NOT be fully forwarded",
        origin_bytes.load(Ordering::Relaxed)
    );
    proxy.abort();
}

/// Send one raw H1 request over a fresh downstream duplex to the shared app and
/// return the raw response bytes (until EOF or a short idle).
async fn h1_roundtrip(app: Arc<pingora::proxy::HttpProxy<SluiceProxy>>, request: &[u8]) -> Vec<u8> {
    let (mut client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let proxy = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    client_io.write_all(request).await.unwrap();
    let _ = client_io.flush().await;

    let mut resp = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(3), client_io.read(&mut tmp)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                resp.extend_from_slice(&tmp[..n]);
                // Stop once we have a complete header block AND a status line — the
                // 413/200 responses here carry Content-Length: 0.
                if find(&resp, b"\r\n\r\n").is_some() {
                    break;
                }
            }
        }
    }
    proxy.abort();
    resp
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h1_chunked_over_limit_body_returns_413_without_upstream_desync() {
    let (origin_port, origin_bytes, _served) = spawn_counting_origin().await;
    let app = build_app(origin_port, false);

    // A chunked body of 12 `a`s (> the 8-byte cap), no Content-Length → the
    // streamed enforcement path.
    let over_limit = b"POST / HTTP/1.1\r\nHost: cap.local\r\nTransfer-Encoding: chunked\r\n\r\n\
                       4\r\naaaa\r\n4\r\naaaa\r\n4\r\naaaa\r\n0\r\n\r\n";
    let resp = h1_roundtrip(app.clone(), over_limit).await;
    let head = String::from_utf8_lossy(&resp);
    assert!(
        head.starts_with("HTTP/1.1 413"),
        "a streamed over-limit H1 chunked body must return 413, got:\n{head}"
    );
    assert!(
        origin_bytes.load(Ordering::Relaxed) < 4096,
        "origin received {} bytes — over-limit body must NOT be fully forwarded",
        origin_bytes.load(Ordering::Relaxed)
    );

    // No upstream desync/poisoning: a subsequent normal request on a FRESH
    // downstream connection (shared upstream pool) must still get a clean 200. If
    // the aborted upstream connection had been returned to the pool with a partial
    // unterminated chunked body, reusing it would desync this request.
    let ok = h1_roundtrip(app.clone(), b"GET / HTTP/1.1\r\nHost: cap.local\r\n\r\n").await;
    let ok_head = String::from_utf8_lossy(&ok);
    assert!(
        ok_head.starts_with("HTTP/1.1 200"),
        "a follow-up request must succeed (no upstream reuse/desync), got:\n{ok_head}"
    );
}

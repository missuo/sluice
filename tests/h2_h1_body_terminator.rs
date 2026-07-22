//! Regression test for round-18: an HTTP/2 request body that ends with an empty
//! DATA frame carrying END_STREAM must be forwarded to an HTTP/1.1 upstream with
//! EXACTLY ONE chunked terminator (`0\r\n\r\n`), not two.
//!
//! Before the fix, `request_body_filter` left the empty end-of-stream chunk as
//! `Some(Bytes::new())`; Pingora's H1 body writer then emitted the terminator for
//! the empty buffer AND again in `finish_body()`, so a strict pooled origin saw a
//! second, bogus terminator (cf. cloudflare/pingora#935) and later mis-assigned a
//! stray response to an unrelated request reusing the pooled connection.
//!
//! This drives the REAL `SluiceProxy` through Pingora's H2→H1 proxy path: an h2c
//! client sends `POST /` with a body ending in an empty END_STREAM DATA frame, and
//! a byte-capturing H1 origin records exactly what reached the wire. A second
//! request on the same client then reuses the pooled upstream connection.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use pingora::apps::{HttpServerOptions, ServerApp};
use pingora::protocols::Stream;
use pingora::proxy::http_proxy;
use pingora::server::configuration::ServerConf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use sluice::config::Config;
use sluice::proxy::SluiceProxy;

fn count_sub(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    let mut n = 0;
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            n += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    n
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Read one request off the wire until the peer goes idle (it is now waiting for
/// our response). Returns the raw bytes, or empty on EOF.
async fn read_request_until_idle(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match tokio::time::timeout(Duration::from_millis(300), stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,                            // EOF
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]), // more data
            Ok(Err(_)) => break,                           // read error
            Err(_) => {
                if !buf.is_empty() {
                    break; // idle after receiving something → request complete
                }
                // still nothing; keep waiting a little longer
            }
        }
    }
    buf
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_to_h1_empty_end_stream_emits_single_terminator() {
    // ---- byte-capturing H1 origin ----
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let conn_count = Arc::new(AtomicUsize::new(0));

    let cap = captured.clone();
    let conns = conn_count.clone();
    let origin = tokio::spawn(async move {
        // Handle a single pooled connection carrying (ideally) BOTH requests.
        while conns.load(Ordering::SeqCst) < 2 {
            let accept = tokio::time::timeout(Duration::from_secs(6), listener.accept()).await;
            let Ok(Ok((mut sock, _))) = accept else { break };
            conns.fetch_add(1, Ordering::SeqCst);
            // Serve up to 2 keep-alive requests on this connection.
            for _ in 0..2 {
                let req = read_request_until_idle(&mut sock).await;
                if req.is_empty() {
                    break;
                }
                cap.lock().unwrap().push(req);
                // Keep-alive 200 so Pingora returns the connection to the pool.
                if sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .is_err()
                {
                    break;
                }
                let _ = sock.flush().await;
            }
        }
    });

    // ---- real SluiceProxy over an h2c duplex ----
    let cfg_text = format!(
        "listener \"127.0.0.1:8443\" {{\n redirect-to-https true\n}}\n\
         site \"test.local\" {{\n upstream \"127.0.0.1:{origin_port}\"\n}}\n"
    );
    let config = Config::parse(&cfg_text).expect("config parses");
    let cfg = Arc::new(ArcSwap::from_pointee(config));

    let conf = Arc::new(ServerConf {
        upstream_keepalive_pool_size: 128,
        ..Default::default()
    });

    let mut app = http_proxy(&conf, SluiceProxy::new(cfg, None));
    let mut opts = HttpServerOptions::default();
    opts.h2c = true; // plaintext h2 over the duplex (no ALPN)
    app.server_options = Some(opts);
    let app = Arc::new(app);

    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let proxy = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    // ---- h2 client: two POSTs, each body ending in an EMPTY END_STREAM frame ----
    let client = tokio::spawn(async move {
        let (mut send_req, connection) = h2::client::handshake(client_io).await.unwrap();
        let conn_task = tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut statuses = Vec::new();
        for _ in 0..2 {
            let mut ready = send_req.ready().await.unwrap();
            let req = http::Request::builder()
                .method("POST")
                .uri("http://test.local/")
                .body(())
                .unwrap();
            // end_of_stream = false → a real request body (chunked to the H1 origin).
            let (resp, mut body) = ready.send_request(req, false).unwrap();
            body.reserve_capacity(5);
            body.send_data(Bytes::from_static(b"hello"), false).unwrap();
            // The trigger: an EMPTY DATA frame with END_STREAM.
            body.send_data(Bytes::new(), true).unwrap();
            let status = resp.await.unwrap().status();
            statuses.push(status.as_u16());
            send_req = ready;
        }
        conn_task.abort();
        statuses
    });

    let statuses = tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("client did not finish in time")
        .expect("client task panicked");
    let _ = tokio::time::timeout(Duration::from_secs(2), proxy).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), origin).await;

    // Both requests succeeded end-to-end.
    assert_eq!(
        statuses,
        vec![200, 200],
        "both proxied requests must return 200"
    );

    let reqs = captured.lock().unwrap();
    assert!(
        !reqs.is_empty(),
        "origin captured no request bytes (proxy never forwarded)"
    );

    // Exactly ONE chunked terminator in the FIRST request's body region.
    let first = &reqs[0];
    let hdr_end = find_sub(first, b"\r\n\r\n").expect("request-1 has a header block");
    let body_region = &first[hdr_end + 4..];
    let terminators = count_sub(body_region, b"0\r\n\r\n");
    assert_eq!(
        terminators,
        1,
        "H2→H1 body must emit exactly ONE chunk terminator, found {terminators} \
         (bytes: {:?})",
        String::from_utf8_lossy(body_region)
    );
    // Also confirm the body content survived intact (chunk-framed "hello").
    assert!(
        find_sub(body_region, b"hello").is_some(),
        "request body content was lost"
    );

    // The pooled upstream connection was safely reused: BOTH requests were served
    // on ONE origin connection (a stray terminator would have poisoned reuse).
    assert_eq!(
        conn_count.load(Ordering::SeqCst),
        1,
        "expected exactly one pooled upstream connection for two requests"
    );
    assert_eq!(
        reqs.len(),
        2,
        "expected two requests on the pooled connection"
    );
}

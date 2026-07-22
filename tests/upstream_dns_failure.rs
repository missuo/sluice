//! Regression test for round-20: an upstream whose hostname fails DNS resolution
//! must yield a bounded `502` — NEVER a panic of the request task, and NEVER a
//! loss of service to an unrelated vhost served by the same proxy.
//!
//! Before the fix, `HttpPeer::new((hostname, port), ..)` ran blocking
//! `std::net::ToSocketAddrs` inside the async request task and `unwrap()`d both the
//! resolver result and its first address, so a resolver outage / NXDOMAIN / empty
//! answer panicked the task and produced an empty client response (cf. pingora
//! #921). Sluice now resolves off the request path under a finite deadline and maps
//! any failure to a `502`.
//!
//! This drives the REAL `SluiceProxy` over an h2c duplex: one vhost points at
//! `nonexistent.invalid` (RFC 6761 reserved — guaranteed non-resolvable), another
//! at a live H1 origin. Requests to the bad vhost get `502`; requests to the good
//! vhost keep returning `200` before AND after the failure.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use pingora::apps::{HttpServerOptions, ServerApp};
use pingora::protocols::Stream;
use pingora::proxy::http_proxy;
use pingora::server::configuration::ServerConf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use sluice::config::Config;
use sluice::proxy::SluiceProxy;

/// A tiny always-200 H1 origin (keep-alive) for the "good" vhost.
async fn spawn_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut tmp = [0u8; 8192];
                loop {
                    // Read one request's headers, then reply keep-alive 200.
                    match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut tmp)).await {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                        Ok(Ok(_)) => {}
                    }
                    if sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                    let _ = sock.flush().await;
                }
            });
        }
    });
    port
}

async fn get(send_req: &mut h2::client::SendRequest<bytes::Bytes>, authority: &str) -> u16 {
    let mut ready = send_req.clone().ready().await.unwrap();
    let req = http::Request::builder()
        .method("GET")
        .uri(format!("http://{authority}/"))
        .body(())
        .unwrap();
    let (resp, _body) = ready.send_request(req, true).unwrap();
    *send_req = ready;
    let status = tokio::time::timeout(Duration::from_secs(8), resp)
        .await
        .expect("upstream request did not complete in time (no bounded error?)")
        .unwrap()
        .status();
    status.as_u16()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_failure_is_bounded_502_and_does_not_take_down_other_vhost() {
    let origin_port = spawn_origin().await;

    // Two vhosts: one live (IP upstream), one whose hostname never resolves.
    let cfg_text = format!(
        "server {{\n upstream-dns-timeout-secs 2\n}}\n\
         listener \"127.0.0.1:8443\" {{\n redirect-to-https true\n}}\n\
         site \"good.local\" {{\n upstream \"127.0.0.1:{origin_port}\"\n}}\n\
         site \"bad.local\" {{\n upstream \"nonexistent.invalid:80\"\n}}\n"
    );
    let config = Config::parse(&cfg_text).expect("config parses");
    let cfg = Arc::new(ArcSwap::from_pointee(config));

    let conf = Arc::new(ServerConf {
        upstream_keepalive_pool_size: 128,
        ..Default::default()
    });
    let mut app = http_proxy(&conf, SluiceProxy::new(cfg, None));
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    app.server_options = Some(opts);
    let app = Arc::new(app);

    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let proxy = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    let client = tokio::spawn(async move {
        let (mut send_req, connection) = h2::client::handshake(client_io).await.unwrap();
        let conn_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        // Good vhost works; the failing vhost returns a bounded 502; the good vhost
        // STILL works afterwards (the DNS failure didn't panic the task or poison
        // the shared proxy / connection pool).
        let s_good_before = get(&mut send_req, "good.local").await;
        let s_bad = get(&mut send_req, "bad.local").await;
        let s_good_after = get(&mut send_req, "good.local").await;
        conn_task.abort();
        (s_good_before, s_bad, s_good_after)
    });

    let (good_before, bad, good_after) = tokio::time::timeout(Duration::from_secs(20), client)
        .await
        .expect("client did not finish — a DNS failure likely panicked/hung the proxy")
        .expect("client task panicked");

    assert_eq!(
        good_before, 200,
        "live vhost must serve 200 before the failure"
    );
    assert_eq!(
        bad, 502,
        "an unresolvable upstream must yield a bounded 502, not a panic/empty response"
    );
    assert_eq!(
        good_after, 200,
        "live vhost must STILL serve 200 after the other vhost's DNS failure"
    );

    // The proxy accept loop must still be alive (not aborted by a panic).
    assert!(
        !proxy.is_finished(),
        "process_new must survive the DNS failure"
    );
    proxy.abort();
}

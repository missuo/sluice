//! Regression test for round-21 finding 1: a hostname backend must fail over
//! across ALL of its resolved addresses, not just the first.
//!
//! Before the fix, `upstream_peer` selected one address by `ctx.tries` — the
//! configured-BACKEND retry counter — so a single hostname backend whose first
//! resolved address was unreachable set `retry=false` and returned 502 even when a
//! later address was healthy (the reviewer reproduced this with a name resolving
//! `[::1, 127.0.0.1]` and an IPv4-only origin: Sluice dialed `[::1]`, got
//! `Connection refused ... retry: false`, and never tried the healthy IPv4).
//!
//! The fix tracks a separate per-backend address-attempt index and exhausts every
//! resolved address before advancing the backend. This test drives the REAL
//! `SluiceProxy` over an h2c duplex with the DNS cache SEEDED (deterministically)
//! to `[[::1]:<port>, 127.0.0.1:<port>]` while the origin listens only on the IPv4
//! address, and asserts the request reaches the healthy address (200).

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

/// A tiny always-200 IPv4-only H1 origin. Returns the bound port.
async fn spawn_ipv4_origin() -> u16 {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostname_backend_fails_over_across_all_resolved_addresses() {
    let origin_port = spawn_ipv4_origin().await;

    // The upstream is the NAME "testhost"; its DNS answer is seeded so the first
    // address (IPv6 loopback, where nothing listens) is unreachable and the second
    // (the IPv4 origin) is healthy — mirroring the reviewer's `[::1, 127.0.0.1]`.
    let cfg_text = format!(
        "listener \"127.0.0.1:8443\" {{\n redirect-to-https true\n}}\n\
         site \"failover.local\" {{\n upstream \"testhost:{origin_port}\"\n}}\n"
    );
    let config = Config::parse(&cfg_text).expect("config parses");
    let cfg = Arc::new(ArcSwap::from_pointee(config));

    let conf = Arc::new(ServerConf {
        upstream_keepalive_pool_size: 128,
        ..Default::default()
    });

    let sluice = SluiceProxy::new(cfg, None);
    // Deterministic multi-address answer: unreachable IPv6 first, healthy IPv4 next.
    let dead_v6: std::net::SocketAddr = format!("[::1]:{origin_port}").parse().unwrap();
    let good_v4: std::net::SocketAddr = format!("127.0.0.1:{origin_port}").parse().unwrap();
    sluice.seed_dns("testhost", origin_port, vec![dead_v6, good_v4]);

    let mut app = http_proxy(&conf, sluice);
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
        let mut ready = send_req.ready().await.unwrap();
        let req = http::Request::builder()
            .method("GET")
            .uri("http://failover.local/")
            .body(())
            .unwrap();
        let (resp, _body) = ready.send_request(req, true).unwrap();
        send_req = ready;
        let _ = &mut send_req;
        let status = tokio::time::timeout(Duration::from_secs(8), resp)
            .await
            .expect("request did not complete — failover likely stalled")
            .unwrap()
            .status();
        conn_task.abort();
        status.as_u16()
    });

    let status = tokio::time::timeout(Duration::from_secs(15), client)
        .await
        .expect("client did not finish")
        .expect("client task panicked");

    assert_eq!(
        status, 200,
        "failover must skip the unreachable first address and reach the healthy one"
    );
    proxy.abort();
}

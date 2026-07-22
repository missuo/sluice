//! End-to-end tests for the static file server through the REAL `SluiceProxy`
//! over a raw H1 duplex: correct status/length/content-type/bytes for small AND
//! large files, a cache hit serves identical bytes, and a symlink-escaping path
//! is still refused (the fd-pinned / `O_NOFOLLOW` SecureDir invariant holds on
//! the cached path too).

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use pingora::apps::{HttpServerOptions, ServerApp};
use pingora::protocols::Stream;
use pingora::proxy::http_proxy;
use pingora::server::configuration::ServerConf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use sluice::config::Config;
use sluice::proxy::SluiceProxy;

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A canonicalized temp docroot (SecureDir::open_ro refuses symlink components,
/// and macOS temp_dir lives under a /var symlink).
fn docroot(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base0 = std::env::temp_dir().join(format!("sluice-static-e2e-{tag}-{n}"));
    let _ = std::fs::remove_dir_all(&base0);
    std::fs::create_dir_all(&base0).unwrap();
    let base = std::fs::canonicalize(&base0).unwrap();
    let root = base.join("www");
    std::fs::create_dir_all(&root).unwrap();
    (base, root)
}

fn build_app(root: &std::path::Path, ttl: u64) -> Arc<pingora::proxy::HttpProxy<SluiceProxy>> {
    let cfg_text = format!(
        "listener \"127.0.0.1:8443\" {{\n redirect-to-https true\n}}\n\
         site \"static.local\" {{\n file-server {{\n root \"{}\"\n index \"index.html\"\n cache-ttl-secs {ttl}\n}}\n}}\n",
        root.display()
    );
    let config = Config::parse(&cfg_text).expect("config parses");
    let cfg = Arc::new(ArcSwap::from_pointee(config));
    let conf = Arc::new(ServerConf::default());
    let mut app = http_proxy(&conf, SluiceProxy::new(cfg, None));
    let mut opts = HttpServerOptions::default();
    opts.h2c = false; // raw H1
    app.server_options = Some(opts);
    Arc::new(app)
}

/// Send one raw H1 request on a fresh downstream duplex; return (head, body).
/// Reads the header block, then exactly Content-Length body bytes.
async fn request(
    app: Arc<pingora::proxy::HttpProxy<SluiceProxy>>,
    raw: &[u8],
) -> (String, Vec<u8>) {
    let (mut client, server_io) = tokio::io::duplex(1024 * 1024);
    let (_sd, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_stream: Stream = Box::new(server_io);
    let proxy = tokio::spawn(async move { app.process_new(server_stream, &shutdown_rx).await });

    client.write_all(raw).await.unwrap();
    let _ = client.flush().await;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    // Read until we have the full header block.
    let head_end = loop {
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p + 4;
        }
        match tokio::time::timeout(Duration::from_secs(5), client.read(&mut tmp)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break buf.len(),
            Ok(Ok(k)) => buf.extend_from_slice(&tmp[..k]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    // Parse Content-Length.
    let clen = head
        .lines()
        .find_map(|l| {
            let l = l.to_ascii_lowercase();
            l.strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < clen {
        match tokio::time::timeout(Duration::from_secs(5), client.read(&mut tmp)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(k)) => body.extend_from_slice(&tmp[..k]),
        }
    }
    proxy.abort();
    (head, body)
}

fn header_val(head: &str, name: &str) -> Option<String> {
    let name = name.to_ascii_lowercase();
    head.lines().find_map(|l| {
        let low = l.to_ascii_lowercase();
        low.strip_prefix(&format!("{name}:"))
            .map(|v| v.trim().to_string())
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serves_small_and_large_files_with_correct_bytes_and_headers() {
    let (base, root) = docroot("bytes");
    std::fs::write(root.join("index.html"), b"<h1>hi</h1>").unwrap();
    let big: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect(); // > 256 KiB inline max
    std::fs::write(root.join("big.bin"), &big).unwrap();
    let app = build_app(&root, 30);

    // Small file at the index (directory request -> index.html).
    let (head, body) = request(app.clone(), b"GET / HTTP/1.1\r\nHost: static.local\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(header_val(&head, "content-length").as_deref(), Some("11"));
    assert_eq!(
        header_val(&head, "content-type").as_deref(),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(&body, b"<h1>hi</h1>");

    // Large file streams with exact length + bytes.
    let (head, body) = request(
        app.clone(),
        b"GET /big.bin HTTP/1.1\r\nHost: static.local\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        header_val(&head, "content-length").as_deref(),
        Some(big.len().to_string().as_str())
    );
    assert_eq!(
        header_val(&head, "content-type").as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(body, big, "large file body must match exactly");

    // HEAD returns the length but no body.
    let (head, body) = request(
        app.clone(),
        b"HEAD / HTTP/1.1\r\nHost: static.local\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(header_val(&head, "content-length").as_deref(), Some("11"));
    assert!(body.is_empty(), "HEAD must have no body");

    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_hit_serves_identical_bytes() {
    let (base, root) = docroot("hit");
    std::fs::write(root.join("a.txt"), b"cached-content").unwrap();
    let app = build_app(&root, 30);

    let (h1, b1) = request(
        app.clone(),
        b"GET /a.txt HTTP/1.1\r\nHost: static.local\r\n\r\n",
    )
    .await;
    let (h2, b2) = request(
        app.clone(),
        b"GET /a.txt HTTP/1.1\r\nHost: static.local\r\n\r\n",
    )
    .await;
    assert!(h1.starts_with("HTTP/1.1 200") && h2.starts_with("HTTP/1.1 200"));
    assert_eq!(b1, b"cached-content");
    assert_eq!(b1, b2, "cache hit must serve byte-identical content");
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn symlink_escape_is_refused_over_http() {
    let (base, root) = docroot("symlink");
    std::fs::write(base.join("secret"), b"TOPSECRET").unwrap();
    std::os::unix::fs::symlink(base.join("secret"), root.join("leak")).unwrap();
    let app = build_app(&root, 30);

    let (head, body) = request(
        app.clone(),
        b"GET /leak HTTP/1.1\r\nHost: static.local\r\n\r\n",
    )
    .await;
    assert!(
        head.starts_with("HTTP/1.1 404"),
        "a symlink under the docroot must 404, never serve the target; got:\n{head}"
    );
    assert!(
        !body.windows(9).any(|w| w == b"TOPSECRET"),
        "secret must never be served"
    );

    // A `..` traversal is refused too.
    let (head, _) = request(
        app.clone(),
        b"GET /../secret HTTP/1.1\r\nHost: static.local\r\n\r\n",
    )
    .await;
    assert!(
        head.starts_with("HTTP/1.1 403") || head.starts_with("HTTP/1.1 404"),
        "traversal must be refused; got:\n{head}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

// A large file's Content-Length and body must come from the SAME open fd. After
// an atomic replacement with a DIFFERENT-size large file, the response must carry
// the NEW file's length AND body (no old-length-paired-with-new-content).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_file_length_and_body_come_from_the_same_open_after_replacement() {
    let (base, root) = docroot("samefd");
    let big1: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
    std::fs::write(root.join("big.bin"), &big1).unwrap();
    let app = build_app(&root, 5);

    let (h1, b1) = request(
        app.clone(),
        b"GET /big.bin HTTP/1.1\r\nHost: static.local\r\n\r\n",
    )
    .await;
    assert!(h1.starts_with("HTTP/1.1 200"), "{h1}");
    assert_eq!(
        header_val(&h1, "content-length").as_deref(),
        Some(big1.len().to_string().as_str())
    );
    assert_eq!(b1, big1);

    // Atomically replace with a different-size large file (rename over the path).
    let big2: Vec<u8> = (0..180_000).map(|i| (i % 97) as u8).collect();
    let tmp = root.join(".big.tmp");
    std::fs::write(&tmp, &big2).unwrap();
    std::fs::rename(&tmp, root.join("big.bin")).unwrap();

    let (h2, b2) = request(
        app.clone(),
        b"GET /big.bin HTTP/1.1\r\nHost: static.local\r\n\r\n",
    )
    .await;
    assert!(h2.starts_with("HTTP/1.1 200"), "{h2}");
    assert_eq!(
        header_val(&h2, "content-length").as_deref(),
        Some(big2.len().to_string().as_str()),
        "Content-Length must match the replacement file (derived from the streamed fd)"
    );
    assert_eq!(
        b2.len(),
        big2.len(),
        "body length must equal Content-Length — same open file description"
    );
    assert_eq!(b2, big2);
    let _ = std::fs::remove_dir_all(&base);
}

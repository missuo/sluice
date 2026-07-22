//! Micro-benchmarks for the CPU-bound hot path (no IO): request-path helpers
//! that run on every request or every config load. These are NOT an end-to-end
//! throughput/P99 benchmark — for that, run the server and a load generator (see
//! `scripts/loadtest.sh`). They exist to catch a regression in the pure-compute
//! cost of the pieces we can measure deterministically.
//!
//!   cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use sluice::config::{build_ketama_ring, stable_hash, Config, Upstream};
use sluice::proxy::{accept_encoding_key, ketama_pick, normalize_path};

fn mk_upstream(host: &str, weight: u32) -> Upstream {
    Upstream {
        host: host.into(),
        port: 8080,
        tls: false,
        sni: host.into(),
        host_header: None,
        verify: false,
        weight,
    }
}

fn bench_hot(c: &mut Criterion) {
    // Path normalization — runs before WAF/deny/routing on every request.
    c.bench_function("normalize_path/traversal+encoded", |b| {
        b.iter(|| normalize_path(black_box("/a/./b/../c/%2e%2e/%61dmin//x")))
    });
    c.bench_function("normalize_path/simple", |b| {
        b.iter(|| normalize_path(black_box("/v1/models/list")))
    });

    // Accept-Encoding cache-key component — runs on every cacheable request.
    c.bench_function("accept_encoding_key", |b| {
        b.iter(|| {
            accept_encoding_key(black_box(
                ["gzip, br;q=0.9, zstd"].iter().map(|s| s.as_bytes()),
            ))
        })
    });

    // Ketama ring build (config load) + lookup (per request under `balance ketama`).
    let servers: Vec<Upstream> = (0..8)
        .map(|i| mk_upstream(&format!("10.0.0.{i}"), 1 + (i % 3) as u32))
        .collect();
    c.bench_function("build_ketama_ring/8-backends", |b| {
        b.iter(|| build_ketama_ring(black_box(&servers)))
    });
    let ring = build_ketama_ring(&servers);
    c.bench_function("ketama_pick", |b| {
        b.iter(|| ketama_pick(black_box(&ring), black_box("203.0.113.42")))
    });
    c.bench_function("stable_hash", |b| {
        b.iter(|| stable_hash(black_box("10.0.0.1:8080-42")))
    });

    // Config parse (SIGHUP reload cost). A representative multi-site config.
    // (No `file-server` here — its docroot must exist and be symlink-free at
    // parse time, which isn't guaranteed in a bench harness.)
    let cfg = "\
server {\n threads 4\n}\n\
listener \"0.0.0.0:80\" {\n redirect-to-https true\n}\n\
site \"a.example\" {\n upstream {\n server \"10.0.0.1:8080\" weight=3\n server \"10.0.0.2:8080\"\n balance \"ketama\"\n }\n cache {\n ttl-secs 60\n }\n}\n\
site \"b.example\" {\n upstream \"10.0.0.3:9000\"\n rate-limit rps=100 burst=200\n waf {\n block field=\"path\" match=r\"(?i)union\\s+select\"\n }\n}\n";
    c.bench_function("config_parse/2-sites", |b| {
        b.iter(|| Config::parse(black_box(cfg)).unwrap())
    });
}

criterion_group!(benches, bench_hot);
criterion_main!(benches);

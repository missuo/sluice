//! Sluice — a config-driven edge proxy on Pingora.
//!
//! The binary (`src/main.rs`) wires listeners and runs the server; this library
//! target exists so unit tests and the `benches/` micro-benchmarks can link the
//! internals (config parsing, the LB hashing, path normalization, the cache
//! key). It is not a stable public API.

pub mod acme;
pub mod certs;
pub mod config;
pub mod dirs;
pub mod diskcache;
pub mod metrics;
pub mod proxy;

//! Prometheus metrics, registered in the default registry that Pingora's
//! `prometheus_http_service` scrapes. Country is the only geo field allowed as a
//! label (low cardinality); ASN/city stay in logs.

use std::sync::{LazyLock, OnceLock};

use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge};

pub static REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "sluice_requests_total",
        "requests by host and status class",
        &["host", "status"]
    )
    .unwrap()
});
pub static RESPONSES: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "sluice_responses_total",
        "responses by host and exact status code",
        &["host", "code"]
    )
    .unwrap()
});
pub static LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    prometheus::register_histogram_vec!(
        "sluice_request_duration_seconds",
        "end-to-end request duration by host",
        &["host"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
    )
    .unwrap()
});
pub static INFLIGHT: LazyLock<IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!("sluice_inflight_requests", "in-flight requests").unwrap()
});
pub static RESP_BYTES: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "sluice_response_bytes_total",
        "response body bytes sent to clients by host",
        &["host"]
    )
    .unwrap()
});
pub static REQ_BYTES: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "sluice_request_bytes_total",
        "request body bytes read from clients by host",
        &["host"]
    )
    .unwrap()
});
pub static UPSTREAM_ERRORS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "sluice_upstream_errors_total",
        "upstream or proxy errors by host",
        &["host"]
    )
    .unwrap()
});
pub static REQUESTS_BY_COUNTRY: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "sluice_requests_by_country_total",
        "requests by client country (from the geoip country header)",
        &["country"]
    )
    .unwrap()
});

/// Pre-resolved per-host metric child handles.
///
/// The hot access path (`logging`) otherwise calls `with_label_values` ~5×/request,
/// which hashes the label strings and looks the child up in the metric's map every
/// time (profiled at ~2.3% of static CPU). These handles bind the `host` label ONCE
/// (lazily, on first use per site — see `Site::metrics`), so subsequent requests
/// just bump a counter with no hashing or allocation. `REQUESTS` is bound per
/// status class (`0xx..5xx`); the per-host-only metrics are bound directly. The
/// two remaining vecs — `sluice_responses_total` (host × exact code) and
/// `sluice_requests_by_country_total` (dynamic country) — can't have their varying
/// label pre-bound, so they stay on `with_label_values` at their call sites.
#[derive(Clone)]
pub struct HostMetrics {
    /// `sluice_requests_total` for this host, indexed by `status / 100` (`0..=5`).
    req_class: [IntCounter; 6],
    latency: Histogram,
    resp_bytes: IntCounter,
    req_bytes: IntCounter,
    upstream_errors: IntCounter,
}

impl HostMetrics {
    /// Resolve every child handle for `host` once. Called lazily so a configured
    /// but never-hit host doesn't pre-populate zero series, and so `--check` /
    /// config parsing don't touch the global registry.
    pub fn new(host: &str) -> HostMetrics {
        let class = |c: &str| REQUESTS.with_label_values(&[host, c]);
        HostMetrics {
            req_class: [
                class("0xx"),
                class("1xx"),
                class("2xx"),
                class("3xx"),
                class("4xx"),
                class("5xx"),
            ],
            latency: LATENCY.with_label_values(&[host]),
            resp_bytes: RESP_BYTES.with_label_values(&[host]),
            req_bytes: REQ_BYTES.with_label_values(&[host]),
            upstream_errors: UPSTREAM_ERRORS.with_label_values(&[host]),
        }
    }

    /// Record one request/response against the pre-bound handles. `status` is the
    /// response status (0 if none was written), `bytes_read`/`bytes_sent` the body
    /// byte counts, `is_error` whether an upstream/proxy error or 502–504 occurred.
    #[inline]
    pub fn record(&self, status: u16, latency_secs: f64, bytes_read: u64, bytes_sent: u64) {
        self.req_class[(status / 100).min(5) as usize].inc();
        self.latency.observe(latency_secs);
        self.resp_bytes.inc_by(bytes_sent);
        self.req_bytes.inc_by(bytes_read);
    }

    #[inline]
    pub fn record_upstream_error(&self) {
        self.upstream_errors.inc();
    }
}

/// The shared handle bundle for the collapsed unmatched-Host label (`"-"`), bound
/// once for the whole process (unmatched Host has no `Site` to hang it off).
pub fn unmatched() -> &'static HostMetrics {
    static UNMATCHED: OnceLock<HostMetrics> = OnceLock::new();
    UNMATCHED.get_or_init(|| HostMetrics::new("-"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Encoder, TextEncoder};

    /// The `gather()` + `TextEncoder` path Pingora's `prometheus_http_service`
    /// uses must produce valid, non-empty Prometheus exposition text. This also
    /// guards the metrics API across the prometheus 0.13 -> 0.14 bump (protobuf 3
    /// / RUSTSEC-2024-0437 fix): a registered+incremented counter must appear in
    /// the scraped text with its `# HELP` / `# TYPE` lines.
    #[test]
    fn gathered_metrics_encode_to_valid_prometheus_text() {
        REQUESTS.with_label_values(&["metrics.test", "2xx"]).inc();
        INFLIGHT.set(1);

        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&prometheus::gather(), &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();

        assert!(
            text.contains("# TYPE sluice_requests_total counter"),
            "expected the counter's TYPE line in:\n{text}"
        );
        assert!(
            text.contains("sluice_requests_total{host=\"metrics.test\",status=\"2xx\"} 1"),
            "expected the incremented sample in:\n{text}"
        );
        assert!(
            text.contains("sluice_inflight_requests 1"),
            "expected the gauge sample in:\n{text}"
        );
    }
}

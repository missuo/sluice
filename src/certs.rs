//! Dynamic, SNI-based certificate store served through Pingora's TLS callback.
//!
//! Certs live in an `ArcSwap<CertStore>` so they can be hot-swapped at runtime
//! (the ACME renewal loop swaps in a new store; a SIGHUP re-reads a `cert-dir`)
//! without restarting or rebinding the listener. A `cert-dir` store is loaded
//! STRICTLY — see [`CertStore::from_dir_strict`] — so a partially-rotated or
//! partially-broken directory is rejected at `--check`, at startup, and on SIGHUP
//! rather than silently serving a store that is missing a host (whose SNI would
//! then fall back to the wrong certificate).

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;

/// A leaf certificate + its chain + private key.
pub struct Cert {
    leaf: X509,
    chain: Vec<X509>,
    key: PKey<Private>,
}

impl Cert {
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Cert, String> {
        let mut stack = X509::stack_from_pem(cert_pem).map_err(|e| e.to_string())?;
        if stack.is_empty() {
            return Err("no certificate found in PEM".to_string());
        }
        let leaf = stack.remove(0);
        let key = PKey::private_key_from_pem(key_pem).map_err(|e| e.to_string())?;
        // Reject a mismatched pair now (a clear load error) rather than letting the
        // TLS handshake fail opaquely later with a cert but no usable key.
        let cert_pub = leaf.public_key().map_err(|e| e.to_string())?;
        if !key.public_eq(&cert_pub) {
            return Err("private key does not match the certificate".to_string());
        }
        Ok(Cert {
            leaf,
            chain: stack,
            key,
        })
    }

    pub fn from_files(cert_path: &str, key_path: &str) -> Result<Cert, String> {
        let c = std::fs::read(cert_path).map_err(|e| format!("{cert_path}: {e}"))?;
        let k = std::fs::read(key_path).map_err(|e| format!("{key_path}: {e}"))?;
        Cert::from_pem(&c, &k)
    }

    /// Load a cert+chain and its private key from a single combined PEM buffer
    /// (concatenated PRIVATE KEY + CERTIFICATE blocks). The ACME store persists
    /// each cert as one file so publishing is a single atomic rename — there is
    /// no window where a fresh key is paired with a stale certificate.
    pub fn from_combined_pem(pem: &[u8]) -> Result<Cert, String> {
        Cert::from_pem(pem, pem)
    }
}

/// The leaf certificate's `notAfter`, as a Unix timestamp (seconds), parsed
/// directly from a PEM buffer.
///
/// The buffer may hold a private key block first (an ACME combined PEM) followed
/// by the certificate chain — the FIRST `CERTIFICATE` block (the leaf) is used.
/// Parsing is done with a pure-Rust ASN.1 parser rather than the TLS backend's
/// X.509 API, because Pingora's TLS facade re-exports `x509::X509` but not the
/// ASN.1 date accessors, and because a pure-Rust parser behaves identically under
/// the OpenSSL and BoringSSL features. Used to schedule ACME renewal from real
/// expiry instead of file mtime; returns `None` on any parse error so the caller
/// can fail safe (treat "can't tell when it expires" as "renew now").
pub fn leaf_not_after_unix(pem: &[u8]) -> Option<i64> {
    for block in x509_parser::pem::Pem::iter_from_buffer(pem) {
        let block = block.ok()?;
        if block.label == "CERTIFICATE" {
            let cert = block.parse_x509().ok()?;
            return Some(cert.validity().not_after.timestamp());
        }
    }
    None
}

/// SNI hostname → cert. The first-inserted cert is the fallback for an unknown SNI.
#[derive(Default, Clone)]
pub struct CertStore {
    map: HashMap<String, Arc<Cert>>,
    fallback: Option<Arc<Cert>>,
}

impl CertStore {
    pub fn insert(&mut self, sni: String, cert: Cert) {
        let cert = Arc::new(cert);
        if self.fallback.is_none() {
            self.fallback = Some(cert.clone());
        }
        // DNS hostnames are case-insensitive, and the SNI a client sends can use
        // any case — so key on the lowercased name (and lowercase the lookup in
        // `pick`). Without this, `B.TEST` missed its `b.test` cert and fell back
        // to the wrong one (a review finding in a multi-cert deployment).
        self.map.insert(sni.to_ascii_lowercase(), cert);
    }

    /// Load every `<host>.crt` + `<host>.key` pair from a directory (the file stem
    /// is the SNI hostname), STRICTLY: ANY problem is a fatal aggregate error and
    /// no store is returned. A problem is a directory-read/entry error, a non-UTF-8
    /// cert OR key filename, a `<host>.crt` with NO matching `<host>.key`, a
    /// `<host>.key` with NO matching `<host>.crt`, or any pair that fails to parse
    /// or whose key doesn't match its cert. An empty directory (no `.crt` at all)
    /// is also an error.
    ///
    /// The `.crt` and `.key` stem SETS must be IDENTICAL — an orphan on EITHER side
    /// is fatal. A stray `.crt` with no key is an obvious half-rotation, but the
    /// INVERSE (a `.key` with no `.crt`) matters just as much: silently ignoring it
    /// would let a directory with a valid `a.test` pair plus a lone `b.test.key`
    /// load as a nonempty "success", after which `b.test` would fall back to
    /// `a.test`'s certificate (a cert mismatch / outage).
    ///
    /// This is used at `--check`, at startup, AND on SIGHUP reload. Because a
    /// partially-rotated directory is REJECTED, a reload never replaces a complete
    /// store with one that is silently missing (or mis-serving) a host; a rejected
    /// load keeps the old store and old config live.
    pub fn from_dir_strict(dir: &str) -> Result<CertStore, String> {
        use std::collections::BTreeSet;
        let mut store = CertStore::default();
        let entries = std::fs::read_dir(dir).map_err(|e| format!("{dir}: {e}"))?;
        let mut errors: Vec<String> = Vec::new();
        // BTreeSet: deterministic (sorted) iteration, so the first-inserted cert —
        // the fallback — is stable, and dedups repeated stems.
        let mut crt_stems: BTreeSet<String> = BTreeSet::new();
        let mut key_stems: BTreeSet<String> = BTreeSet::new();
        for e in entries {
            let e = match e {
                Ok(e) => e,
                Err(err) => {
                    errors.push(format!("directory entry error: {err}"));
                    continue;
                }
            };
            let p = e.path();
            match p.extension().and_then(|x| x.to_str()) {
                Some("crt") => match p.file_stem().and_then(|s| s.to_str()) {
                    Some(stem) => {
                        crt_stems.insert(stem.to_string());
                    }
                    None => errors.push(format!("cert file {p:?} has a non-UTF-8 name")),
                },
                Some("key") => match p.file_stem().and_then(|s| s.to_str()) {
                    Some(stem) => {
                        key_stems.insert(stem.to_string());
                    }
                    None => errors.push(format!("key file {p:?} has a non-UTF-8 name")),
                },
                _ => {}
            }
        }
        if crt_stems.is_empty() {
            errors.push("no <host>.crt files present".to_string());
        }
        // Both half-rotations are fatal: a `.crt` with no `.key`, AND a `.key`
        // with no `.crt`.
        for orphan in crt_stems.difference(&key_stems) {
            errors.push(format!(
                "{orphan}.crt has no matching {orphan}.key (partial/half-rotated pair)"
            ));
        }
        for orphan in key_stems.difference(&crt_stems) {
            errors.push(format!(
                "{orphan}.key has no matching {orphan}.crt (partial/half-rotated pair)"
            ));
        }
        // Parse only when the two stem sets are identical (every host has both
        // files) — otherwise the aggregate error above is already fatal.
        if errors.is_empty() {
            for host in &crt_stems {
                let crt = format!("{dir}/{host}.crt");
                let key = format!("{dir}/{host}.key");
                match Cert::from_files(&crt, &key) {
                    Ok(cert) => store.insert(host.clone(), cert),
                    Err(e) => errors.push(format!("{host}: {e}")),
                }
            }
        }
        if !errors.is_empty() {
            return Err(format!("{dir}: {}", errors.join("; ")));
        }
        Ok(store)
    }

    fn pick(&self, sni: &str) -> Option<&Arc<Cert>> {
        self.map
            .get(&sni.to_ascii_lowercase())
            .or(self.fallback.as_ref())
    }

    /// Number of SNI hostnames with a loaded cert (for logging/tests).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Whether a (lowercased) SNI hostname has a specific cert (not just fallback).
    pub fn has_host(&self, sni: &str) -> bool {
        self.map.contains_key(&sni.to_ascii_lowercase())
    }
}

/// Pingora TLS callback: selects a cert from the store by SNI at handshake time.
pub struct DynamicCert {
    pub store: Arc<ArcSwap<CertStore>>,
}

#[async_trait]
impl TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let store = self.store.load();
        let sni = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or("")
            .to_string();
        match store.pick(&sni) {
            Some(cert) => {
                if let Err(e) = ext::ssl_use_certificate(ssl, &cert.leaf) {
                    log::error!("tls: set certificate for SNI {sni:?} failed: {e}");
                }
                if let Err(e) = ext::ssl_use_private_key(ssl, &cert.key) {
                    log::error!("tls: set private key for SNI {sni:?} failed: {e}");
                }
                for ch in &cert.chain {
                    if let Err(e) = ext::ssl_add_chain_cert(ssl, ch) {
                        log::error!("tls: add chain cert for SNI {sni:?} failed: {e}");
                    }
                }
            }
            // No cert and no fallback → the handshake will fail closed. Log it so a
            // dead :443 (e.g. an ACME cert that never issued) is diagnosable.
            None => log::warn!(
                "tls: no certificate for SNI {sni:?} (and no fallback); handshake will fail"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A self-signed P-256 cert + its key (CN=combined.test). Only used to prove
    // the PEM *parsing* works — `from_combined_pem` checks the key matches the
    // cert, not that the cert is unexpired, so expiry is irrelevant here.
    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiA8cUWegRzXpawhI\neFydTRVo8XZtftk6JVs188iFnD+hRANCAAR1ETweKF6kwa1+xSYIYY4xqmzd5C/a\nzSuE7b+1Ttbj/aVo080GbqY3HAim/bruu0QmzMK3sVAghAJ5w3CdBMZF\n-----END PRIVATE KEY-----\n";
    const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBhDCCASugAwIBAgIUY2qpVCvSrv2kWbErBo0p+mjSMXIwCgYIKoZIzj0EAwIw\nGDEWMBQGA1UEAwwNY29tYmluZWQudGVzdDAeFw0yNjA3MjEwNTQ3MjdaFw0yNjA3\nMjMwNTQ3MjdaMBgxFjAUBgNVBAMMDWNvbWJpbmVkLnRlc3QwWTATBgcqhkjOPQIB\nBggqhkjOPQMBBwNCAAR1ETweKF6kwa1+xSYIYY4xqmzd5C/azSuE7b+1Ttbj/aVo\n080GbqY3HAim/bruu0QmzMK3sVAghAJ5w3CdBMZFo1MwUTAdBgNVHQ4EFgQUJ9Xi\nYOgnJn8BV/yHfFoRm1GBRN0wHwYDVR0jBBgwFoAUJ9XiYOgnJn8BV/yHfFoRm1GB\nRN0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAa6hsc1tumjZ47\nCI6cmgo0rMMBB4g43NcZPlpVUCr4FAIgXv8E0zt+D/AOpzdcFXNp/YdsL+H87Cmj\nRaa4N45/YA0=\n-----END CERTIFICATE-----\n";

    #[test]
    fn combined_pem_loads_cert_and_key_from_one_buffer() {
        // publish_cert writes key then cert into one file; from_combined_pem must
        // read both back and confirm they're a matching pair.
        let combined = format!("{KEY_PEM}\n{CERT_PEM}");
        Cert::from_combined_pem(combined.as_bytes())
            .expect("combined key+cert PEM should load as a matching pair");
        // Order-independence: cert-then-key must work too.
        let reversed = format!("{CERT_PEM}\n{KEY_PEM}");
        Cert::from_combined_pem(reversed.as_bytes()).expect("cert-then-key order should also load");
    }

    #[test]
    fn mismatched_pair_is_rejected() {
        // A cert with no matching key in the buffer must fail (guards against the
        // old two-file scheme's new-key+old-cert hazard).
        assert!(Cert::from_combined_pem(CERT_PEM.as_bytes()).is_err());
    }

    #[test]
    fn sni_match_is_case_insensitive() {
        // Two distinct certs (same fixture bytes, but each `insert` makes its own
        // Arc). The first inserted becomes the fallback. A mixed-case SNI must
        // resolve to its OWN cert, not fall back — the review found `B.TEST`
        // returning `a.test`'s cert.
        let mk = || Cert::from_pem(CERT_PEM.as_bytes(), KEY_PEM.as_bytes()).unwrap();
        let mut store = CertStore::default();
        store.insert("a.test".into(), mk()); // fallback
        store.insert("b.test".into(), mk());
        let picked = store.pick("B.TEST").cloned().expect("some cert");
        let fallback = store.pick("a.test").cloned().expect("some cert");
        assert!(
            !Arc::ptr_eq(&picked, &fallback),
            "B.TEST must resolve to b.test's cert, not the fallback"
        );
        // Sanity: it IS the same Arc as the lowercase lookup.
        let lower = store.pick("b.test").cloned().unwrap();
        assert!(Arc::ptr_eq(&picked, &lower));
    }

    fn tmp() -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!(
            "sluice-cert-strict-{n}-{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_pair(dir: &std::path::Path, host: &str) {
        std::fs::write(dir.join(format!("{host}.crt")), CERT_PEM).unwrap();
        std::fs::write(dir.join(format!("{host}.key")), KEY_PEM).unwrap();
    }

    #[test]
    fn from_dir_strict_rejects_any_partial_or_broken_pair() {
        // A complete two-host dir loads.
        let dir = tmp();
        write_pair(&dir, "a.test");
        write_pair(&dir, "b.test");
        let store = CertStore::from_dir_strict(dir.to_str().unwrap()).expect("two valid pairs");
        assert_eq!(store.len(), 2);
        assert!(store.has_host("a.test") && store.has_host("b.test"));

        // A `.crt` with NO matching `.key` (half-rotation) is fatal — no partial store.
        std::fs::remove_file(dir.join("b.test.key")).unwrap();
        let Err(e) = CertStore::from_dir_strict(dir.to_str().unwrap()) else {
            panic!("a .crt with no .key must be rejected");
        };
        assert!(e.contains("no matching b.test.key"), "{e}");

        // The INVERSE half-rotation — a `.key` with NO `.crt` — is equally fatal.
        // Otherwise a valid `a.test` pair plus a lone `b.test.key` would load as a
        // nonempty success and `b.test` would serve `a.test`'s fallback cert.
        let inv = tmp();
        write_pair(&inv, "a.test");
        std::fs::write(inv.join("b.test.key"), KEY_PEM).unwrap(); // key, no cert
        let Err(e) = CertStore::from_dir_strict(inv.to_str().unwrap()) else {
            panic!("a .key with no .crt must be rejected (inverse half-rotation)");
        };
        assert!(e.contains("no matching b.test.crt"), "{e}");

        // A malformed `.crt` is fatal.
        std::fs::write(dir.join("b.test.key"), KEY_PEM).unwrap();
        std::fs::write(dir.join("b.test.crt"), b"not a cert").unwrap();
        assert!(CertStore::from_dir_strict(dir.to_str().unwrap()).is_err());

        // An empty directory is an error.
        let empty = tmp();
        assert!(CertStore::from_dir_strict(empty.to_str().unwrap()).is_err());

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&inv).ok();
        std::fs::remove_dir_all(&empty).ok();
    }
}

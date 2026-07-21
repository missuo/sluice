//! Dynamic, SNI-based certificate store served through Pingora's TLS callback.
//!
//! Certs live in an `ArcSwap<CertStore>` so they can be hot-swapped at runtime
//! (the ACME renewal loop swaps in a new store) without restarting or rebinding
//! the listener. NOTE: a `cert-dir` store is currently built once at startup and
//! is NOT re-read on SIGHUP — rotating a file in `cert-dir` needs a restart.

use std::collections::HashMap;
use std::path::Path;
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
        self.map.insert(sni, cert);
    }

    /// Load every `<host>.crt` + `<host>.key` pair from a directory; the file
    /// stem is the SNI hostname. A single bad pair is logged and skipped (it does
    /// not abort the whole load); only an empty result is an error.
    pub fn from_dir(dir: &str) -> Result<CertStore, String> {
        let mut store = CertStore::default();
        let entries = std::fs::read_dir(dir).map_err(|e| format!("{dir}: {e}"))?;
        let mut hosts: Vec<String> = Vec::new();
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("crt") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    hosts.push(stem.to_string());
                }
            }
        }
        hosts.sort();
        for host in hosts {
            let crt = format!("{dir}/{host}.crt");
            let key = format!("{dir}/{host}.key");
            if Path::new(&key).exists() {
                match Cert::from_files(&crt, &key) {
                    Ok(cert) => store.insert(host, cert),
                    Err(e) => log::error!("cert-dir: skipping {host}: {e}"),
                }
            }
        }
        if store.map.is_empty() {
            return Err(format!("no usable <host>.crt/<host>.key pairs in {dir}"));
        }
        Ok(store)
    }

    fn pick(&self, sni: &str) -> Option<&Arc<Cert>> {
        self.map.get(sni).or(self.fallback.as_ref())
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

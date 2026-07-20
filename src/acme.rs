//! Automatic TLS via ACME (Let's Encrypt) over HTTP-01.
//!
//! Runs in its own thread with a small Tokio runtime. For each site host it
//! provisions (or renews) a certificate and writes it into the shared cert
//! store, which the TLS callback serves by SNI. The HTTP-01 challenge is
//! answered by the `:80` listener via the shared challenge map.
//!
//! Requires each domain to resolve to this server with port 80 reachable —
//! behind a proxying CDN (orange-cloud Cloudflare) HTTP-01 won't validate.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};

use crate::certs::{Cert, CertStore};
use crate::config::AcmeCfg;

/// HTTP-01 challenge token → key authorization, served on `:80`.
pub type ChallengeStore = Arc<ArcSwap<HashMap<String, String>>>;

pub fn spawn(
    cfg: AcmeCfg,
    domains: Vec<String>,
    cert_store: Arc<ArcSwap<CertStore>>,
    challenges: ChallengeStore,
) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("acme: cannot start runtime: {e}");
                return;
            }
        };
        let _ = std::fs::create_dir_all(&cfg.cache_dir);
        load_cached(&cfg, &domains, &cert_store);
        rt.block_on(async move {
            loop {
                for d in &domains {
                    if !needs_cert(&cfg, d) {
                        continue;
                    }
                    match provision(&cfg, d, &challenges).await {
                        Ok((cert_pem, key_pem)) => {
                            let _ = std::fs::write(format!("{}/{}.crt", cfg.cache_dir, d), &cert_pem);
                            let _ = std::fs::write(format!("{}/{}.key", cfg.cache_dir, d), &key_pem);
                            match Cert::from_pem(cert_pem.as_bytes(), key_pem.as_bytes()) {
                                Ok(c) => {
                                    let mut store = (**cert_store.load()).clone();
                                    store.insert(d.clone(), c);
                                    cert_store.store(Arc::new(store));
                                    log::info!("acme: issued/renewed cert for {d}");
                                }
                                Err(e) => log::error!("acme: {d}: parse issued cert: {e}"),
                            }
                        }
                        Err(e) => log::error!("acme: {d}: {e}"),
                    }
                }
                tokio::time::sleep(Duration::from_secs(12 * 3600)).await;
            }
        });
    });
}

fn load_cached(cfg: &AcmeCfg, domains: &[String], cert_store: &Arc<ArcSwap<CertStore>>) {
    let mut store = (**cert_store.load()).clone();
    let mut any = false;
    for d in domains {
        let crt = format!("{}/{}.crt", cfg.cache_dir, d);
        let key = format!("{}/{}.key", cfg.cache_dir, d);
        if let Ok(c) = Cert::from_files(&crt, &key) {
            store.insert(d.clone(), c);
            any = true;
        }
    }
    if any {
        cert_store.store(Arc::new(store));
    }
}

/// Re-issue if the cert is missing or older than 60 days (LE certs last 90).
fn needs_cert(cfg: &AcmeCfg, domain: &str) -> bool {
    let crt = format!("{}/{}.crt", cfg.cache_dir, domain);
    match std::fs::metadata(&crt).and_then(|m| m.modified()) {
        Ok(mtime) => mtime
            .elapsed()
            .map(|e| e > Duration::from_secs(60 * 24 * 3600))
            .unwrap_or(true),
        Err(_) => true,
    }
}

async fn provision(
    cfg: &AcmeCfg,
    domain: &str,
    challenges: &ChallengeStore,
) -> Result<(String, String), String> {
    let dir = if cfg.staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };
    let contact = format!("mailto:{}", cfg.contact);
    let (account, _creds) = Account::create(
        &NewAccount {
            contact: &[&contact],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        dir,
        None,
    )
    .await
    .map_err(|e| format!("account: {e}"))?;

    let ids = [Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder { identifiers: &ids })
        .await
        .map_err(|e| format!("new order: {e}"))?;

    let auths = order.authorizations().await.map_err(|e| format!("authz: {e}"))?;
    for auth in &auths {
        if auth.status != AuthorizationStatus::Pending {
            continue;
        }
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or("no HTTP-01 challenge offered")?;
        let keyauth = order.key_authorization(challenge);
        let mut map = (**challenges.load()).clone();
        map.insert(challenge.token.clone(), keyauth.as_str().to_string());
        challenges.store(Arc::new(map));
        order
            .set_challenge_ready(&challenge.url)
            .await
            .map_err(|e| format!("challenge ready: {e}"))?;
    }

    // Poll until the order is ready (validated) or invalid.
    let mut tries = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let state = order.refresh().await.map_err(|e| format!("refresh: {e}"))?;
        match state.status {
            OrderStatus::Ready => break,
            OrderStatus::Invalid => {
                return Err("order invalid — HTTP-01 validation failed (is the domain \
                            resolving to this server with :80 open, not behind a proxy?)"
                    .to_string())
            }
            _ => {}
        }
        tries += 1;
        if tries > 45 {
            return Err("order not ready after 90s".to_string());
        }
    }

    // Generate the cert keypair + CSR, finalize, fetch the chain.
    let key_pair = rcgen::KeyPair::generate().map_err(|e| format!("keygen: {e}"))?;
    let params =
        rcgen::CertificateParams::new(vec![domain.to_string()]).map_err(|e| format!("csr params: {e}"))?;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| format!("csr: {e}"))?;
    order
        .finalize(csr.der())
        .await
        .map_err(|e| format!("finalize: {e}"))?;

    let mut tries = 0;
    let cert_pem = loop {
        if let Some(pem) = order.certificate().await.map_err(|e| format!("certificate: {e}"))? {
            break pem;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        tries += 1;
        if tries > 30 {
            return Err("certificate not issued after 60s".to_string());
        }
    };

    Ok((cert_pem, key_pair.serialize_pem()))
}

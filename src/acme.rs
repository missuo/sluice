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
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
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
        create_private_dir(&cfg.cache_dir);
        load_cached(&cfg, &domains, &cert_store);
        rt.block_on(async move {
            // One ACME account, created once and reused for every domain and every
            // renewal cycle. Registering a fresh account per provision would hit
            // Let's Encrypt's new-account rate limit as soon as there are several
            // domains. Credentials are cached per environment (staging vs prod).
            let account = match get_account(&cfg).await {
                Ok(a) => a,
                Err(e) => {
                    log::error!("acme: cannot initialize account: {e}");
                    return;
                }
            };
            loop {
                for d in &domains {
                    if !needs_cert(&cfg, d) {
                        continue;
                    }
                    match provision(&account, d, &challenges).await {
                        Ok((cert_pem, key_pem)) => {
                            let _ = std::fs::write(format!("{}/{}.crt", cfg.cache_dir, d), &cert_pem);
                            // The private key must not be world-readable.
                            if let Err(e) =
                                write_private(&format!("{}/{}.key", cfg.cache_dir, d), key_pem.as_bytes())
                            {
                                log::warn!("acme: {d}: could not write private key: {e}");
                            }
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

/// Create the cache dir with owner-only permissions (it holds private keys).
fn create_private_dir(dir: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir);
    }
    #[cfg(not(unix))]
    let _ = std::fs::create_dir_all(dir);
}

/// Write a file containing secret material with mode 0600 (owner read/write).
fn write_private(path: &str, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)
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

/// Load the cached ACME account for this environment, or register a new one and
/// persist its credentials. Cached per environment (staging and production are
/// distinct accounts on distinct directory URLs).
async fn get_account(cfg: &AcmeCfg) -> Result<Account, String> {
    let env = if cfg.staging { "staging" } else { "production" };
    let creds_path = format!("{}/account-{env}.json", cfg.cache_dir);

    if let Ok(bytes) = std::fs::read(&creds_path) {
        match serde_json::from_slice::<AccountCredentials>(&bytes) {
            Ok(creds) => match Account::builder()
                .map_err(|e| format!("account builder: {e}"))?
                .from_credentials(creds)
                .await
            {
                Ok(account) => return Ok(account),
                Err(e) => log::warn!("acme: cached account unusable ({e}); registering a new one"),
            },
            Err(e) => log::warn!("acme: cached account creds corrupt ({e}); registering a new one"),
        }
    }

    let dir = if cfg.staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };
    let contact = format!("mailto:{}", cfg.contact);
    let (account, creds) = Account::builder()
        .map_err(|e| format!("account builder: {e}"))?
        .create(
            &NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            dir.to_owned(),
            None,
        )
        .await
        .map_err(|e| format!("account: {e}"))?;
    // Account credentials embed the account private key — write them 0600.
    match serde_json::to_vec(&creds) {
        Ok(json) => {
            if let Err(e) = write_private(&creds_path, &json) {
                log::warn!("acme: could not cache account credentials to {creds_path}: {e}");
            }
        }
        Err(e) => log::warn!("acme: could not serialize account credentials: {e}"),
    }
    Ok(account)
}

async fn provision(
    account: &Account,
    domain: &str,
    challenges: &ChallengeStore,
) -> Result<(String, String), String> {
    let ids = [Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&ids))
        .await
        .map_err(|e| format!("new order: {e}"))?;

    // Publish the HTTP-01 response for each pending authorization, then tell the
    // server it's ready. `authorizations()` borrows the order, so scope it so the
    // borrow is released before we poll the order below.
    let mut published: Vec<String> = Vec::new();
    {
        let mut authzs = order.authorizations();
        while let Some(res) = authzs.next().await {
            let mut authz = res.map_err(|e| format!("authz: {e}"))?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                _ => continue,
            }
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or("no HTTP-01 challenge offered")?;
            let token = challenge.token.clone();
            let keyauth = challenge.key_authorization().as_str().to_string();
            let mut map = (**challenges.load()).clone();
            map.insert(token.clone(), keyauth);
            challenges.store(Arc::new(map));
            published.push(token);
            challenge
                .set_ready()
                .await
                .map_err(|e| format!("challenge ready: {e}"))?;
        }
    }

    // Back off until the order is validated (Ready) or fails.
    let poll = order.poll_ready(&RetryPolicy::default()).await;
    // The tokens have served their purpose — stop answering them on :80 and keep
    // the challenge map from growing across renewals (do this whatever the outcome).
    if !published.is_empty() {
        let mut map = (**challenges.load()).clone();
        for t in &published {
            map.remove(t);
        }
        challenges.store(Arc::new(map));
    }
    let status = poll.map_err(|e| format!("poll ready: {e}"))?;
    if status != OrderStatus::Ready {
        return Err(format!(
            "order {status:?} — HTTP-01 validation failed (is the domain resolving \
             to this server with :80 open, not behind a proxy?)"
        ));
    }

    // finalize() generates the cert key pair internally and returns its PEM.
    let key_pem = order.finalize().await.map_err(|e| format!("finalize: {e}"))?;
    let cert_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| format!("certificate: {e}"))?;

    Ok((cert_pem, key_pem))
}

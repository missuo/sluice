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
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
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
            // renewal cycle (a fresh account per provision would hit Let's
            // Encrypt's new-account rate limit). A transient failure retries — it
            // must NOT permanently kill the renewal thread.
            let mut account: Option<Account> = None;
            loop {
                if account.is_none() {
                    match get_account(&cfg).await {
                        Ok(a) => account = Some(a),
                        Err(e) => {
                            log::error!("acme: account init failed ({e}); retrying in 60s");
                            tokio::time::sleep(Duration::from_secs(60)).await;
                            continue;
                        }
                    }
                }
                let account = account.as_ref().unwrap();
                for d in &domains {
                    if !needs_cert(&cfg, d) {
                        continue;
                    }
                    match provision(account, d, &challenges).await {
                        Ok((cert_pem, key_pem)) => {
                            // Publish atomically: write temps, verify they load as a
                            // matching pair, then rename into place. A disk-full /
                            // short write during renewal can't clobber the previous
                            // valid cert — the old files stay until the new pair is
                            // proven good.
                            if let Err(e) = publish_cert(&cfg, d, &cert_pem, &key_pem) {
                                log::warn!("acme: {d}: could not publish cert: {e}; keeping old");
                                continue;
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

/// Per-environment combined cert+key file path, so switching `staging` on/off
/// doesn't serve the other environment's (e.g. untrusted staging) cert. Key and
/// full chain live in ONE file so publishing is a single atomic rename.
fn cert_path(cfg: &AcmeCfg, domain: &str) -> String {
    let env = if cfg.staging { "staging" } else { "production" };
    format!("{}/{env}-{domain}.pem", cfg.cache_dir)
}

/// Publish a new cert atomically. Key + full chain are concatenated into a single
/// buffer, verified to load as a matching pair, written to a pid-tagged temp
/// (fsync'd), then `rename`d over the live file in ONE step. A single file means
/// there is never a window where a new key is paired with an old certificate —
/// the previous two-file scheme could crash between its two renames and leave a
/// mismatched key+cert that broke TLS load on the next boot. The parent directory
/// is fsync'd after the rename so a power loss can't lose the new name, and the
/// pid tag keeps two processes (a rolling upgrade) from racing on one temp path.
fn publish_cert(cfg: &AcmeCfg, domain: &str, cert_pem: &str, key_pem: &str) -> Result<(), String> {
    let path = cert_path(cfg, domain);
    let mut combined = String::with_capacity(key_pem.len() + cert_pem.len() + 1);
    combined.push_str(key_pem.trim_end());
    combined.push('\n');
    combined.push_str(cert_pem);
    // Prove the bytes load as a matching pair before anything durable is written.
    Cert::from_combined_pem(combined.as_bytes()).map_err(|e| format!("verify new pair: {e}"))?;

    let tmp = format!("{path}.tmp.{}", std::process::id());
    if let Err(e) = write_private(&tmp, combined.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write temp: {e}"));
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("install: {e}"));
    }
    sync_parent_dir(&path);
    Ok(())
}

/// fsync the directory holding `path` so a freshly `rename`d entry survives a
/// crash/power loss (a rename is only durable once its directory is synced).
fn sync_parent_dir(path: &str) {
    #[cfg(unix)]
    if let Some(parent) = std::path::Path::new(path).parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

/// Create the cache dir with owner-only permissions (it holds private keys).
fn create_private_dir(dir: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir);
    }
    #[cfg(not(unix))]
    let _ = std::fs::create_dir_all(dir);
}

/// Write a file containing secret material with mode 0600 (owner read/write).
fn write_private(path: &str, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
        // mode() only applies on create — force 0600 on an existing (possibly
        // world-readable) file too.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        // Durably flush secret material before a rename relies on it.
        f.sync_all()
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut f = std::fs::File::create(path)?;
        f.write_all(data)?;
        f.sync_all()
    }
}

fn load_cached(cfg: &AcmeCfg, domains: &[String], cert_store: &Arc<ArcSwap<CertStore>>) {
    let mut store = (**cert_store.load()).clone();
    let mut any = false;
    for d in domains {
        let path = cert_path(cfg, d);
        if let Ok(c) = Cert::from_combined_file(&path) {
            store.insert(d.clone(), c);
            any = true;
        }
    }
    if any {
        cert_store.store(Arc::new(store));
    }
}

/// Re-issue if the cached pair won't load as a valid, matching cert, or if it's
/// older than 60 days (LE certs last 90). Loading the pair (not just checking the
/// files exist) means a broken/mismatched/partial cached cert is re-issued
/// promptly instead of sitting unusable for 60 days. A future mtime (clock skew)
/// is treated as "fresh" so a skewed clock can't trigger an every-12h re-issue
/// storm. (mtime, not X.509 notAfter, because pingora's TLS facade doesn't
/// re-export the asn1 module needed to read notAfter portably across OpenSSL/
/// BoringSSL — tracked for later.)
fn needs_cert(cfg: &AcmeCfg, domain: &str) -> bool {
    let path = cert_path(cfg, domain);
    if Cert::from_combined_file(&path).is_err() {
        return true;
    }
    match std::fs::metadata(&path).and_then(|m| m.modified()) {
        Ok(mtime) => mtime
            .elapsed()
            .map(|e| e > Duration::from_secs(60 * 24 * 3600))
            .unwrap_or(false),
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
    let mut published: Vec<String> = Vec::new();
    let result = provision_inner(account, domain, challenges, &mut published).await;
    // Always unpublish the challenge tokens — on success AND on any early error —
    // so :80 stops answering them and the challenge map can't grow across
    // retries/renewals.
    if !published.is_empty() {
        let mut map = (**challenges.load()).clone();
        for t in &published {
            map.remove(t);
        }
        challenges.store(Arc::new(map));
    }
    result
}

async fn provision_inner(
    account: &Account,
    domain: &str,
    challenges: &ChallengeStore,
    published: &mut Vec<String>,
) -> Result<(String, String), String> {
    let ids = [Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&ids))
        .await
        .map_err(|e| format!("new order: {e}"))?;

    // Publish the HTTP-01 response for each pending authorization, then tell the
    // server it's ready. `authorizations()` borrows the order, so scope it so the
    // borrow is released before we poll the order below.
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
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|e| format!("poll ready: {e}"))?;
    if status != OrderStatus::Ready {
        return Err(format!(
            "order {status:?} — HTTP-01 validation failed (is the domain resolving \
             to this server with :80 open, not behind a proxy?)"
        ));
    }

    // finalize() generates the cert key pair internally and returns its PEM.
    let key_pem = order
        .finalize()
        .await
        .map_err(|e| format!("finalize: {e}"))?;
    let cert_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| format!("certificate: {e}"))?;

    Ok((cert_pem, key_pem))
}

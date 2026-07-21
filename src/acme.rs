//! Automatic TLS via ACME (Let's Encrypt) over HTTP-01.
//!
//! Runs in its own thread with a small Tokio runtime. For each site host it
//! provisions (or renews) a certificate and writes it into the shared cert
//! store, which the TLS callback serves by SNI. The HTTP-01 challenge is
//! answered by the `:80` listener via the shared challenge map.
//!
//! On disk each cert is ONE combined PEM (`<env>-<domain>.pem`, private key +
//! full chain) so publishing is a single atomic rename. Certs from the older
//! two-file layout (`.crt`/`.key`) are loaded and migrated on startup — an
//! upgrade never drops TLS while waiting on the CA.
//!
//! The cache dir holds private keys, so it is verified before use (a real
//! directory, owned by the running user, mode 0700 — never behind a symlink)
//! and every secret write goes through an O_EXCL temp + atomic rename.
//!
//! Requires each domain to resolve to this server with port 80 reachable —
//! behind a proxying CDN (orange-cloud Cloudflare) HTTP-01 won't validate.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Provision the ACME cache dir and load any cached certs into the store
/// SYNCHRONOUSLY (before the caller starts the `:443` listener), then spawn the
/// background renewal thread. Returns `Err` if the cache dir can't be pinned —
/// the caller (main) treats that as fatal, so a misconfigured ACME dir fails
/// startup loudly instead of silently leaving `:443` with an empty cert store.
pub fn spawn(
    cfg: AcmeCfg,
    domains: Vec<String>,
    cert_store: Arc<ArcSwap<CertStore>>,
    challenges: ChallengeStore,
) -> Result<(), String> {
    // Pin the cache dir by fd (create 0700 if missing, verify owner, chmod).
    // Every key read/write is then done relative to THIS fd via openat/renameat,
    // so a local user can't reroute a write by swapping a parent component.
    // Config load already did a read-only `validate`; provisioning (which
    // mutates) happens here at startup, never during `--check`.
    let dir = crate::dirs::SecureDir::provision(&cfg.cache_dir)
        .map_err(|e| format!("acme cache-dir {}: {e}", cfg.cache_dir))?;
    // Load cached/migrated certs before we return, so the listener binds with
    // certs already in the store rather than a window of empty `:443`.
    load_cached(&cfg, &dir, &domains, &cert_store);

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
        rt.block_on(async move {
            // One ACME account, created once and reused for every domain and every
            // renewal cycle (a fresh account per provision would hit Let's
            // Encrypt's new-account rate limit). A transient failure retries — it
            // must NOT permanently kill the renewal thread.
            let mut account: Option<Account> = None;
            loop {
                if account.is_none() {
                    match get_account(&cfg, &dir).await {
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
                    if !needs_cert(&cfg, &dir, d) {
                        continue;
                    }
                    match provision(account, d, &challenges).await {
                        Ok((cert_pem, key_pem)) => {
                            // Publish atomically: one combined temp file, verified,
                            // then a single rename. A disk-full / short write / crash
                            // during renewal can't clobber the previous valid cert.
                            if let Err(e) = publish_cert(&cfg, &dir, d, &cert_pem, &key_pem) {
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
    Ok(())
}

/// Per-environment combined cert+key file NAME (a single basename under the
/// pinned cache dir — not a path), so switching `staging` on/off doesn't serve
/// the other environment's cert. Key + full chain live in ONE file so publishing
/// is a single atomic rename.
fn cert_name(cfg: &AcmeCfg, domain: &str) -> String {
    let env = if cfg.staging { "staging" } else { "production" };
    format!("{env}-{domain}.pem")
}

/// The pre-combined-file layout: cert and key as two separate file NAMES. Only
/// read for the startup migration; never written anymore.
fn legacy_names(cfg: &AcmeCfg, domain: &str) -> (String, String) {
    let env = if cfg.staging { "staging" } else { "production" };
    (format!("{env}-{domain}.crt"), format!("{env}-{domain}.key"))
}

/// Publish a new cert atomically, relative to the pinned cache dir `dir`. Key +
/// full chain are concatenated, verified to load as a matching pair, then
/// installed with ONE `renameat` (O_EXCL temp). A single file means there is
/// never a window where a new key pairs with an old certificate.
fn publish_cert(
    cfg: &AcmeCfg,
    dir: &crate::dirs::SecureDir,
    domain: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<(), String> {
    let name = cert_name(cfg, domain);
    let mut combined = String::with_capacity(key_pem.len() + cert_pem.len() + 1);
    combined.push_str(key_pem.trim_end());
    combined.push('\n');
    combined.push_str(cert_pem);
    // Prove the bytes load as a matching pair before anything durable is written.
    Cert::from_combined_pem(combined.as_bytes()).map_err(|e| format!("verify new pair: {e}"))?;
    write_secret_atomic(dir, &name, combined.as_bytes(), None).map_err(|e| format!("install: {e}"))
}

/// Write secret material to `name` in the pinned dir atomically: an
/// unpredictably-named `O_EXCL` temp (openat, mode 0600), optional `mtime`
/// stamped on the temp fd BEFORE fsync+rename (so freshness is durable with the
/// content — a migrated old cert can't look freshly written and skip renewal),
/// then `renameat` over `name`.
///
/// Durability vs. commit are distinguished: once the `renameat` SUCCEEDS the
/// file IS the live cert, so a subsequent directory-fsync failure is a
/// durability warning (might not survive a power loss) — NOT a publish failure.
/// Returning an error there would make the caller skip updating the in-memory
/// cert store while the new cert (and its fresh mtime) already sit on disk,
/// leaving the process serving the OLD cert until restart — a review finding.
fn write_secret_atomic(
    dir: &crate::dirs::SecureDir,
    name: &str,
    data: &[u8],
    mtime: Option<std::time::SystemTime>,
) -> std::io::Result<()> {
    use std::io::Write;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = format!(
        ".tmp.{}.{}.{nonce}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let write_tmp = (|| -> std::io::Result<()> {
        let mut f = dir.create_new(&tmp)?;
        f.write_all(data)?;
        if let Some(t) = mtime {
            f.set_modified(t)?; // BEFORE sync+rename → durable with content
        }
        f.sync_all()
    })();
    if let Err(e) = write_tmp {
        let _ = dir.remove(&tmp);
        return Err(e);
    }
    if let Err(e) = dir.rename(&tmp, name) {
        let _ = dir.remove(&tmp);
        return Err(e);
    }
    // Rename committed — the cert is live. fsync the dir for power-loss
    // durability, but a failure here is non-fatal (log only).
    if let Err(e) = dir.sync() {
        log::warn!("acme: {name}: installed but dir fsync failed ({e}); durable on next sync");
    }
    Ok(())
}

/// Load a domain's cached cert (relative to the pinned dir): the combined `.pem`
/// if present, else a legacy `.crt`/`.key` pair — which keeps serving across an
/// upgrade AND is migrated to the combined layout on the spot, preserving the
/// legacy mtime (stamped atomically on the temp) so renewal timing is unchanged.
/// If the conversion can't be written, the pair is still served from memory and
/// `needs_cert` re-issues. Legacy files are left in place for rollback.
fn load_combined(dir: &crate::dirs::SecureDir, name: &str) -> Option<Cert> {
    use std::io::Read;
    let mut buf = Vec::new();
    dir.open_read(name).ok()?.read_to_end(&mut buf).ok()?;
    Cert::from_combined_pem(&buf).ok()
}

fn load_or_migrate(cfg: &AcmeCfg, dir: &crate::dirs::SecureDir, domain: &str) -> Option<Cert> {
    use std::io::Read;
    let name = cert_name(cfg, domain);
    if let Some(c) = load_combined(dir, &name) {
        return Some(c);
    }
    let (crt, key) = legacy_names(cfg, domain);
    let mut cbuf = Vec::new();
    let mut kbuf = Vec::new();
    let legacy_mtime = {
        let mut cf = dir.open_read(&crt).ok()?;
        let mtime = cf.metadata().and_then(|m| m.modified()).ok();
        cf.read_to_end(&mut cbuf).ok()?;
        mtime
    };
    dir.open_read(&key).ok()?.read_to_end(&mut kbuf).ok()?;
    let cert = Cert::from_pem(&cbuf, &kbuf).ok()?; // verifies the pair matches
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&kbuf).trim_end(),
        String::from_utf8_lossy(&cbuf)
    );
    if write_secret_atomic(dir, &name, combined.as_bytes(), legacy_mtime).is_ok() {
        log::info!("acme: {domain}: migrated legacy .crt/.key to combined {name}");
    } else {
        let _ = dir.remove(&name);
        log::warn!("acme: {domain}: cannot migrate legacy pair; will re-issue");
    }
    Some(cert)
}

fn load_cached(
    cfg: &AcmeCfg,
    dir: &crate::dirs::SecureDir,
    domains: &[String],
    cert_store: &Arc<ArcSwap<CertStore>>,
) {
    let mut store = (**cert_store.load()).clone();
    let mut any = false;
    for d in domains {
        if let Some(c) = load_or_migrate(cfg, dir, d) {
            store.insert(d.clone(), c);
            any = true;
        }
    }
    if any {
        cert_store.store(Arc::new(store));
    }
}

/// Re-issue if the cached cert won't load as a valid pair, or if it's older than
/// 60 days (LE certs last 90). A future mtime (clock skew) is treated as "fresh"
/// so a skewed clock can't trigger an every-12h re-issue storm. (mtime, not
/// X.509 notAfter — pingora's TLS facade doesn't re-export the asn1 module;
/// tracked in KNOWN_ISSUES.)
fn needs_cert(cfg: &AcmeCfg, dir: &crate::dirs::SecureDir, domain: &str) -> bool {
    let name = cert_name(cfg, domain);
    let Ok(f) = dir.open_read(&name) else {
        return true;
    };
    let mut buf = Vec::new();
    use std::io::Read;
    let mut f2 = f;
    if f2.read_to_end(&mut buf).is_err() || Cert::from_combined_pem(&buf).is_err() {
        return true;
    }
    match f2.metadata().and_then(|m| m.modified()) {
        Ok(mtime) => mtime
            .elapsed()
            .map(|e| e > Duration::from_secs(60 * 24 * 3600))
            .unwrap_or(false),
        Err(_) => true,
    }
}

/// Load the cached ACME account for this environment, or register a new one and
/// persist its credentials (relative to the pinned dir). Cached per environment.
async fn get_account(cfg: &AcmeCfg, dir: &crate::dirs::SecureDir) -> Result<Account, String> {
    use std::io::Read;
    let env = if cfg.staging { "staging" } else { "production" };
    let creds_name = format!("account-{env}.json");

    if let Ok(mut f) = dir.open_read(&creds_name) {
        let mut bytes = Vec::new();
        if f.read_to_end(&mut bytes).is_ok() {
            match serde_json::from_slice::<AccountCredentials>(&bytes) {
                Ok(creds) => match Account::builder()
                    .map_err(|e| format!("account builder: {e}"))?
                    .from_credentials(creds)
                    .await
                {
                    Ok(account) => return Ok(account),
                    Err(e) => {
                        log::warn!("acme: cached account unusable ({e}); registering a new one")
                    }
                },
                Err(e) => {
                    log::warn!("acme: cached account creds corrupt ({e}); registering a new one")
                }
            }
        }
    }

    let url = if cfg.staging {
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
            url.to_owned(),
            None,
        )
        .await
        .map_err(|e| format!("account: {e}"))?;
    // Account credentials embed the account private key — write 0600 via O_EXCL
    // temp + atomic rename in the pinned dir.
    match serde_json::to_vec(&creds) {
        Ok(json) => {
            if let Err(e) = write_secret_atomic(dir, &creds_name, &json, None) {
                log::warn!("acme: could not cache account credentials: {e}");
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // Same self-signed P-256 fixture as certs::tests (CN=combined.test). Only
    // pair-matching is checked by the loaders, so expiry is irrelevant here.
    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiA8cUWegRzXpawhI\neFydTRVo8XZtftk6JVs188iFnD+hRANCAAR1ETweKF6kwa1+xSYIYY4xqmzd5C/a\nzSuE7b+1Ttbj/aVo080GbqY3HAim/bruu0QmzMK3sVAghAJ5w3CdBMZF\n-----END PRIVATE KEY-----\n";
    const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBhDCCASugAwIBAgIUY2qpVCvSrv2kWbErBo0p+mjSMXIwCgYIKoZIzj0EAwIw\nGDEWMBQGA1UEAwwNY29tYmluZWQudGVzdDAeFw0yNjA3MjEwNTQ3MjdaFw0yNjA3\nMjMwNTQ3MjdaMBgxFjAUBgNVBAMMDWNvbWJpbmVkLnRlc3QwWTATBgcqhkjOPQIB\nBggqhkjOPQMBBwNCAAR1ETweKF6kwa1+xSYIYY4xqmzd5C/azSuE7b+1Ttbj/aVo\n080GbqY3HAim/bruu0QmzMK3sVAghAJ5w3CdBMZFo1MwUTAdBgNVHQ4EFgQUJ9Xi\nYOgnJn8BV/yHfFoRm1GBRN0wHwYDVR0jBBgwFoAUJ9XiYOgnJn8BV/yHfFoRm1GB\nRN0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAa6hsc1tumjZ47\nCI6cmgo0rMMBB4g43NcZPlpVUCr4FAIgXv8E0zt+D/AOpzdcFXNp/YdsL+H87Cmj\nRaa4N45/YA0=\n-----END CERTIFICATE-----\n";

    fn test_dir(tag: &str) -> (String, crate::dirs::SecureDir) {
        let d = std::env::temp_dir().join(format!("sluice-acme-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let path = d.to_str().unwrap().to_string();
        let sd = crate::dirs::SecureDir::provision(&path).unwrap();
        (path, sd)
    }

    fn set_mtime_secs_ago(path: &str, secs: u64) {
        let t = std::time::SystemTime::now() - Duration::from_secs(secs);
        let d = t.duration_since(std::time::UNIX_EPOCH).unwrap();
        let ts = libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as _,
        };
        let c = std::ffi::CString::new(path).unwrap();
        assert_eq!(
            unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), [ts, ts].as_ptr(), 0) },
            0
        );
    }

    fn mtime_unix(path: &str) -> u64 {
        std::fs::metadata(path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn migrates_legacy_pair_and_preserves_renewal_clock() {
        let (path, dir) = test_dir("mig");
        let cfg = AcmeCfg {
            contact: "t@example.com".into(),
            staging: false,
            cache_dir: path.clone(),
        };
        let (crt, key) = legacy_names(&cfg, "legacy.test");
        std::fs::write(format!("{path}/{crt}"), CERT_PEM).unwrap();
        std::fs::write(format!("{path}/{key}"), KEY_PEM).unwrap();
        // A 70-day-old legacy cert: must keep serving AND be due for renewal.
        set_mtime_secs_ago(&format!("{path}/{crt}"), 70 * 24 * 3600);

        let c = load_or_migrate(&cfg, &dir, "legacy.test");
        assert!(c.is_some(), "legacy pair must load and serve");
        let pem = format!("{path}/{}", cert_name(&cfg, "legacy.test"));
        Cert::from_combined_pem(&std::fs::read(&pem).unwrap())
            .expect("migrated combined file must load");
        // The migrated file keeps the legacy mtime → the 60-day clock says renew.
        let drift = mtime_unix(&pem).abs_diff(mtime_unix(&format!("{path}/{crt}")));
        assert!(drift < 5, "migration must preserve mtime (drift {drift}s)");
        assert!(
            needs_cert(&cfg, &dir, "legacy.test"),
            "70d-old cert must renew"
        );

        // A fresh legacy pair must NOT trigger an immediate CA round-trip.
        std::fs::remove_file(&pem).unwrap();
        set_mtime_secs_ago(&format!("{path}/{crt}"), 5 * 24 * 3600);
        load_or_migrate(&cfg, &dir, "legacy.test").unwrap();
        assert!(
            !needs_cert(&cfg, &dir, "legacy.test"),
            "5d-old cert is fresh"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    // (dir owner/mode/symlink + openat safety is tested in crate::dirs; here we
    // cover the ACME atomic secret write: 0600, mtime stamp, symlink-safe.)
    #[test]
    fn write_secret_atomic_0600_and_stamps_mtime() {
        use std::os::unix::fs::PermissionsExt;
        let (path, dir) = test_dir("wpa");
        write_secret_atomic(&dir, "creds.json", b"secret", None).unwrap();
        let target = format!("{path}/creds.json");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"secret");
        // Overwrite in place (rename replaces the name).
        write_secret_atomic(&dir, "creds.json", b"new-secret", None).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new-secret");
        // An explicit mtime is stamped atomically with the content.
        let old = std::time::SystemTime::now() - Duration::from_secs(90 * 24 * 3600);
        write_secret_atomic(&dir, "stamped.pem", b"x", Some(old)).unwrap();
        let got = std::fs::metadata(format!("{path}/stamped.pem"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            got.duration_since(old).unwrap_or_default() < Duration::from_secs(5),
            "mtime must be the stamped value, not now"
        );
        let _ = std::fs::remove_dir_all(&path);
    }
}

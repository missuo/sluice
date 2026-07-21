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
        // The cache dir was already validated + canonicalized at config load
        // (crate::dirs::secure_owned_dir, so `--check` and startup fail loudly
        // rather than the background thread silently disabling ACME). Re-verify
        // here as defense in depth (TOCTOU between load and now) and re-canonical
        // in case the config path was relative.
        let cache_dir = match crate::dirs::secure_owned_dir(&cfg.cache_dir) {
            Ok(canon) => canon,
            Err(e) => {
                log::error!("acme: cache-dir {}: {e}; ACME disabled", cfg.cache_dir);
                return;
            }
        };
        let cfg = AcmeCfg { cache_dir, ..cfg };
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
                            // Publish atomically: one combined temp file, verified,
                            // then a single rename. A disk-full / short write / crash
                            // during renewal can't clobber the previous valid cert.
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

/// The pre-combined-file layout: cert and key as two separate files. Only read
/// for the startup migration; never written anymore.
fn legacy_cert_paths(cfg: &AcmeCfg, domain: &str) -> (String, String) {
    let env = if cfg.staging { "staging" } else { "production" };
    (
        format!("{}/{env}-{domain}.crt", cfg.cache_dir),
        format!("{}/{env}-{domain}.key", cfg.cache_dir),
    )
}

/// Publish a new cert atomically. Key + full chain are concatenated into a
/// single buffer, verified to load as a matching pair, then installed with ONE
/// atomic rename (O_EXCL temp, fsync of file and parent dir — errors propagate,
/// durability is not best-effort). A single file means there is never a window
/// where a new key is paired with an old certificate — the earlier two-file
/// scheme could crash between its two renames and leave a mismatched pair that
/// broke TLS load on the next boot.
fn publish_cert(cfg: &AcmeCfg, domain: &str, cert_pem: &str, key_pem: &str) -> Result<(), String> {
    let path = cert_path(cfg, domain);
    let mut combined = String::with_capacity(key_pem.len() + cert_pem.len() + 1);
    combined.push_str(key_pem.trim_end());
    combined.push('\n');
    combined.push_str(cert_pem);
    // Prove the bytes load as a matching pair before anything durable is written.
    Cert::from_combined_pem(combined.as_bytes()).map_err(|e| format!("verify new pair: {e}"))?;
    write_private_atomic(&path, combined.as_bytes(), None).map_err(|e| format!("install: {e}"))
}

/// Write secret material to `path` atomically: a unique temp sibling opened with
/// `create_new` (O_CREAT|O_EXCL — refuses to follow a pre-planted symlink and
/// never truncates an existing file), mode 0600 from birth. If `mtime` is given
/// it is stamped on the TEMP fd BEFORE the fsync+rename — so the freshness
/// timestamp is durable atomically with the content, closing the crash window
/// where a rename could land before a separate post-rename `utimensat` ran (a
/// migrated old cert would otherwise look freshly written and skip renewal). The
/// temp is fsync'd, renamed over `path` (rename replaces a symlink at the
/// destination rather than following it), then the parent dir is fsync'd. Any
/// failure cleans up the temp and propagates.
fn write_private_atomic(
    path: &str,
    data: &[u8],
    mtime: Option<std::time::SystemTime>,
) -> std::io::Result<()> {
    use std::io::Write;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = format!(
        "{path}.tmp.{}.{}.{nonce}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let res = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        if let Some(t) = mtime {
            f.set_modified(t)?; // stamped BEFORE sync+rename → durable with content
        }
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        sync_parent_dir(path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// fsync the directory holding `path` so a freshly `rename`d entry survives a
/// crash/power loss (a rename is only durable once its directory is synced).
fn sync_parent_dir(path: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = std::path::Path::new(path).parent() {
        let dir = std::fs::File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

/// Load a domain's cached cert: the combined `.pem` if present, else a legacy
/// `.crt`/`.key` pair — which keeps serving across an upgrade AND is converted
/// to the combined layout on the spot. The legacy file's mtime is stamped onto
/// the migrated file ATOMICALLY (on the temp, before rename — see
/// `write_private_atomic`), so a crash can't leave a migrated cert that looks
/// freshly written and skips renewal past its real expiry. If the conversion
/// can't be written, the pair is still served from memory and `needs_cert`
/// re-issues via the CA. Legacy files are left in place so a rollback to the
/// old binary still works.
fn load_or_migrate(cfg: &AcmeCfg, domain: &str) -> Option<Cert> {
    let path = cert_path(cfg, domain);
    if let Ok(c) = Cert::from_combined_file(&path) {
        return Some(c);
    }
    let (crt, key) = legacy_cert_paths(cfg, domain);
    let cert = Cert::from_files(&crt, &key).ok()?; // also verifies the pair matches
    let legacy_mtime = std::fs::metadata(&crt).and_then(|m| m.modified()).ok();
    match (std::fs::read_to_string(&crt), std::fs::read_to_string(&key)) {
        (Ok(cert_pem), Ok(key_pem)) => {
            let combined = format!("{}\n{cert_pem}", key_pem.trim_end());
            let ok = Cert::from_combined_pem(combined.as_bytes()).is_ok()
                && write_private_atomic(&path, combined.as_bytes(), legacy_mtime).is_ok();
            if ok {
                log::info!("acme: {domain}: migrated legacy .crt/.key to combined {path}");
            } else {
                let _ = std::fs::remove_file(&path);
                log::warn!("acme: {domain}: cannot migrate legacy pair; will re-issue");
            }
        }
        _ => log::warn!("acme: {domain}: legacy pair unreadable; will re-issue"),
    }
    Some(cert)
}

fn load_cached(cfg: &AcmeCfg, domains: &[String], cert_store: &Arc<ArcSwap<CertStore>>) {
    let mut store = (**cert_store.load()).clone();
    let mut any = false;
    for d in domains {
        if let Some(c) = load_or_migrate(cfg, d) {
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
/// BoringSSL — tracked in KNOWN_ISSUES.)
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
    // Account credentials embed the account private key — 0600, O_EXCL temp,
    // atomic rename (a predictable-path symlink can't capture or truncate).
    match serde_json::to_vec(&creds) {
        Ok(json) => {
            if let Err(e) = write_private_atomic(&creds_path, &json, None) {
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // Same self-signed P-256 fixture as certs::tests (CN=combined.test). Only
    // pair-matching is checked by the loaders, so expiry is irrelevant here.
    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiA8cUWegRzXpawhI\neFydTRVo8XZtftk6JVs188iFnD+hRANCAAR1ETweKF6kwa1+xSYIYY4xqmzd5C/a\nzSuE7b+1Ttbj/aVo080GbqY3HAim/bruu0QmzMK3sVAghAJ5w3CdBMZF\n-----END PRIVATE KEY-----\n";
    const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBhDCCASugAwIBAgIUY2qpVCvSrv2kWbErBo0p+mjSMXIwCgYIKoZIzj0EAwIw\nGDEWMBQGA1UEAwwNY29tYmluZWQudGVzdDAeFw0yNjA3MjEwNTQ3MjdaFw0yNjA3\nMjMwNTQ3MjdaMBgxFjAUBgNVBAMMDWNvbWJpbmVkLnRlc3QwWTATBgcqhkjOPQIB\nBggqhkjOPQMBBwNCAAR1ETweKF6kwa1+xSYIYY4xqmzd5C/azSuE7b+1Ttbj/aVo\n080GbqY3HAim/bruu0QmzMK3sVAghAJ5w3CdBMZFo1MwUTAdBgNVHQ4EFgQUJ9Xi\nYOgnJn8BV/yHfFoRm1GBRN0wHwYDVR0jBBgwFoAUJ9XiYOgnJn8BV/yHfFoRm1GB\nRN0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAa6hsc1tumjZ47\nCI6cmgo0rMMBB4g43NcZPlpVUCr4FAIgXv8E0zt+D/AOpzdcFXNp/YdsL+H87Cmj\nRaa4N45/YA0=\n-----END CERTIFICATE-----\n";

    fn test_dir(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("sluice-acme-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_str().unwrap().to_string()
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
        let dir = test_dir("mig");
        let cfg = AcmeCfg {
            contact: "t@example.com".into(),
            staging: false,
            cache_dir: dir.clone(),
        };
        let (crt, key) = legacy_cert_paths(&cfg, "legacy.test");
        std::fs::write(&crt, CERT_PEM).unwrap();
        std::fs::write(&key, KEY_PEM).unwrap();
        // A 70-day-old legacy cert: must keep serving AND be due for renewal.
        set_mtime_secs_ago(&crt, 70 * 24 * 3600);

        let c = load_or_migrate(&cfg, "legacy.test");
        assert!(c.is_some(), "legacy pair must load and serve");
        let pem = cert_path(&cfg, "legacy.test");
        Cert::from_combined_file(&pem).expect("migrated combined file must load");
        // The migrated file keeps the legacy mtime → the 60-day clock says renew.
        let drift = mtime_unix(&pem).abs_diff(mtime_unix(&crt));
        assert!(drift < 5, "migration must preserve mtime (drift {drift}s)");
        assert!(needs_cert(&cfg, "legacy.test"), "70d-old cert must renew");

        // A fresh legacy pair must NOT trigger an immediate CA round-trip.
        std::fs::remove_file(&pem).unwrap();
        set_mtime_secs_ago(&crt, 5 * 24 * 3600);
        load_or_migrate(&cfg, "legacy.test").unwrap();
        assert!(!needs_cert(&cfg, "legacy.test"), "5d-old cert is fresh");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // (cache-dir owner/mode/symlink hardening is now shared and tested in
    // crate::dirs; here we only cover the ACME-specific atomic secret write.)

    #[test]
    fn write_private_atomic_0600_symlink_safe_and_stamps_mtime() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("wpa");
        let target = format!("{dir}/creds.json");
        write_private_atomic(&target, b"secret", None).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&target).unwrap(), b"secret");
        // A symlink pre-planted at the FINAL path must be replaced (rename
        // unlinks the name), never followed into its target.
        let victim = format!("{dir}/victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let attacked = format!("{dir}/attacked.json");
        std::os::unix::fs::symlink(&victim, &attacked).unwrap();
        write_private_atomic(&attacked, b"new-secret", None).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert_eq!(std::fs::read(&attacked).unwrap(), b"new-secret");
        assert!(!std::fs::symlink_metadata(&attacked)
            .unwrap()
            .file_type()
            .is_symlink());
        // An explicit mtime is stamped atomically with the content.
        let old = std::time::SystemTime::now() - Duration::from_secs(90 * 24 * 3600);
        let stamped = format!("{dir}/stamped.pem");
        write_private_atomic(&stamped, b"x", Some(old)).unwrap();
        let got = std::fs::metadata(&stamped).unwrap().modified().unwrap();
        assert!(
            got.duration_since(old).unwrap_or_default() < Duration::from_secs(5),
            "mtime must be the stamped value, not now"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

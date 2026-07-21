//! Security-sensitive directory validation shared by the ACME store and the
//! disk cache.
//!
//! `secure_owned_dir` returns the CANONICAL path, which callers must use for
//! all subsequent file construction — so a symlink swapped into a parent
//! component later can't re-route writes. The final component must not itself
//! be a symlink (that is the local-attacker shape, and canonicalizing it away
//! could otherwise let a root process chmod a root-owned system directory the
//! link points at). Ownership and mode are checked/fixed via `fstat`/`fchmod`
//! on an opened FD, so there is no check-to-chmod window on the inode.

#[cfg(unix)]
pub fn secure_owned_dir(dir: &str) -> Result<String, String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::os::unix::io::AsRawFd;
    // Create 0700 if missing (ok if it exists — verified below).
    let _ = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir);
    // The configured path's FINAL component must be a real directory, not a
    // symlink — refuse the classic pre-planted-link attack outright.
    let lmd = std::fs::symlink_metadata(dir).map_err(|e| format!("{dir}: {e}"))?;
    if lmd.file_type().is_symlink() {
        return Err(format!(
            "{dir}: is a symlink; refusing to store files behind one"
        ));
    }
    // Canonicalize so parent-path symlinks (a legitimate admin setup, e.g.
    // /var/lib -> /data/lib, or macOS /tmp -> /private/tmp) are resolved ONCE
    // here, and every later open uses the resolved path.
    let canon = std::fs::canonicalize(dir).map_err(|e| format!("{dir}: {e}"))?;
    let f = std::fs::File::open(&canon).map_err(|e| format!("{}: {e}", canon.display()))?;
    let md = f.metadata().map_err(|e| e.to_string())?; // fstat on the open FD
    if !md.is_dir() {
        return Err(format!("{}: not a directory", canon.display()));
    }
    let euid = unsafe { libc::geteuid() };
    if md.uid() != euid {
        return Err(format!(
            "{}: owned by uid {} but sluice runs as uid {euid}",
            canon.display(),
            md.uid()
        ));
    }
    // fchmod the FD we just fstat'd — same inode, no TOCTOU.
    if unsafe { libc::fchmod(f.as_raw_fd(), 0o700) } != 0 {
        return Err(format!(
            "{}: cannot chmod 0700: {}",
            canon.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(canon.to_string_lossy().into_owned())
}

#[cfg(not(unix))]
pub fn secure_owned_dir(dir: &str) -> Result<String, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{dir}: {e}"))?;
    Ok(dir.to_string())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn rejects_symlink_fixes_mode_returns_canonical() {
        let base = std::env::temp_dir().join(format!("sluice-dirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o777)).unwrap();

        let canon = secure_owned_dir(real.to_str().unwrap()).expect("owned real dir accepted");
        // Canonical (macOS /tmp is a symlink into /private) and locked to 0700.
        assert_eq!(
            canon,
            std::fs::canonicalize(&real)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        );
        let mode = std::fs::metadata(&real).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700, "pre-existing 0777 dir must be tightened");

        // Final-component symlink is refused even though its target is ours.
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(secure_owned_dir(link.to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}

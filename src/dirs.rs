//! Security-sensitive directory handling for the ACME store and disk cache.
//!
//! The private directories hold secrets (ACME keys) or attacker-influenced
//! content (cache entries). A path string is NOT a safe handle: after we
//! validate `/x/cache`, a local user who controls `/x` can rename `cache` away
//! and drop a symlink in its place, so a later path-based `open`/`rename` writes
//! through the link (a real cross-UID exploit found in review).
//!
//! `SecureDir` pins the validated directory by its **file descriptor** and does
//! every subsequent operation with `openat`/`mkdirat`/`renameat`/`unlinkat`
//! relative to that fd, one component at a time with `O_NOFOLLOW`. A pinned
//! inode can't be re-routed by swapping a parent path component, and a symlink
//! planted for any component fails the open instead of being followed.
//!
//! `validate()` is read-only (for `--check`): it never creates or chmods.
//! `provision()` (startup only) creates the dir, verifies owner, and locks it to
//! 0700 via `fchmod` on the opened fd — so there is no check-to-chmod window and
//! `--check` never mutates the filesystem.

#[cfg(unix)]
pub use unix::SecureDir;

#[cfg(unix)]
pub fn validate(path: &str) -> Result<(), String> {
    unix::validate(path)
}
#[cfg(not(unix))]
pub fn validate(_path: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
mod unix {
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    fn errno() -> io::Error {
        io::Error::last_os_error()
    }

    /// Validate a single path component used with `*at` calls: no separator, no
    /// NUL, and never `.`/`..` (which would escape the pinned dir).
    fn component(name: &str) -> io::Result<CString> {
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\0')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsafe path component",
            ));
        }
        CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL"))
    }

    /// Open a single directory component relative to `dir` with `O_NOFOLLOW`,
    /// creating it 0700 if missing. If the component is a symlink, accept it ONLY
    /// when the link is owned by root or by us (a trusted system symlink); an
    /// attacker-owned link is refused. Returns the opened directory fd.
    fn open_or_make_dir(dir: &OwnedFd, comp: &str, euid: libc::uid_t) -> io::Result<OwnedFd> {
        let c = component(comp)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
        if fd >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let e = errno();
        if e.raw_os_error() == Some(libc::ENOENT) {
            // Create it (0700) and reopen no-follow. A racing symlink swap makes
            // the reopen fail (ELOOP) → error, never a followed link.
            if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
                let me = errno();
                if me.raw_os_error() != Some(libc::EEXIST) {
                    return Err(me);
                }
            }
            let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
            if fd >= 0 {
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
            // fall through to the symlink/other-error handling below
        }
        // Not ENOENT (or the reopen failed): if it's a symlink, allow only a
        // trusted-owner one (root/us); otherwise refuse.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
            && (st.st_mode & libc::S_IFMT) == libc::S_IFLNK
        {
            if st.st_uid == 0 || st.st_uid == euid {
                // Trusted system symlink (e.g. macOS /var) — follow it.
                let follow = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
                let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), follow) };
                if fd >= 0 {
                    return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
                }
                return Err(errno());
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("untrusted symlink (owned by uid {})", st.st_uid),
            ));
        }
        Err(e)
    }

    /// A directory pinned by its fd. All IO is relative to it via `*at` syscalls.
    pub struct SecureDir {
        fd: OwnedFd,
    }

    impl std::os::unix::io::AsRawFd for SecureDir {
        /// For `fstatvfs` on the pinned dir (disk-cache free-space check). Do NOT
        /// use this to re-open by path — that would defeat the fd pinning.
        fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    impl SecureDir {
        fn raw(&self) -> RawFd {
            self.fd.as_raw_fd()
        }

        /// Startup: create + open `path` component-by-component from a trusted
        /// root fd (`/` for an absolute path, the CWD for a relative one), with
        /// `O_NOFOLLOW` at EVERY level — not just the last. This closes the
        /// startup parent-symlink TOCTOU: the old code let `mkdir -p` + a single
        /// `open(path, O_NOFOLLOW)` follow a symlinked PARENT that a low-priv user
        /// swapped in between `--check` and provisioning, so provisioning could
        /// pin (and chmod 0700) an attacker-chosen root-owned victim dir.
        ///
        /// A symlink component is accepted ONLY if the link itself is owned by
        /// root or by us — so legitimate system symlinks (macOS `/var` →
        /// `private/var`) still work, while an attacker's link (owned by their
        /// uid) is refused. Real directory components are opened by fd and never
        /// re-resolved. The final dir must be owned by us; it's `fchmod`'d 0700.
        pub fn provision(path: &str) -> Result<SecureDir, String> {
            let comps: Vec<&str> = path
                .split('/')
                .filter(|c| !c.is_empty() && *c != ".")
                .collect();
            if comps.contains(&"..") {
                return Err(format!("{path}: must not contain `..`"));
            }
            let euid = unsafe { libc::geteuid() };
            // Trusted anchor: "/" (root, not a symlink) or "." (our CWD).
            let anchor = if path.starts_with('/') { "/" } else { "." };
            let ac = CString::new(anchor).map_err(|_| "bad anchor".to_string())?;
            let afd = unsafe {
                libc::open(
                    ac.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if afd < 0 {
                return Err(format!("{anchor}: {}", errno()));
            }
            let mut cur = unsafe { OwnedFd::from_raw_fd(afd) };
            for comp in comps {
                cur = open_or_make_dir(&cur, comp, euid)
                    .map_err(|e| format!("{path}: component {comp:?}: {e}"))?;
            }
            // fstat the final OPEN fd → owner check with no TOCTOU.
            let md = File::from(cur.try_clone().map_err(|e| e.to_string())?)
                .metadata()
                .map_err(|e| e.to_string())?;
            if !md.is_dir() {
                return Err(format!("{path}: not a directory"));
            }
            use std::os::unix::fs::MetadataExt;
            if md.uid() != euid {
                return Err(format!(
                    "{path}: owned by uid {} but sluice runs as uid {euid}",
                    md.uid()
                ));
            }
            if unsafe { libc::fchmod(cur.as_raw_fd(), 0o700) } != 0 {
                return Err(format!("{path}: cannot chmod 0700: {}", errno()));
            }
            Ok(SecureDir { fd: cur })
        }

        /// Open (creating if needed, 0700) a SUB-directory by a single component,
        /// relative to this dir's fd, `O_NOFOLLOW` — a symlinked component is
        /// refused. Used only on the cache WRITE path (a miss).
        pub fn sub(&self, name: &str) -> io::Result<SecureDir> {
            let c = component(name)?;
            // mkdirat: ignore EEXIST, surface anything else.
            if unsafe { libc::mkdirat(self.raw(), c.as_ptr(), 0o700) } != 0 {
                let e = errno();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(e);
                }
            }
            self.sub_open(name)
        }

        /// Open an EXISTING sub-directory (never creates it), `O_NOFOLLOW`. Used
        /// on read/lookup/reaper paths so a cache MISS can't make an attacker
        /// mint unbounded empty shard directories by varying the URL.
        pub fn sub_open(&self, name: &str) -> io::Result<SecureDir> {
            let c = component(name)?;
            let fd = unsafe {
                libc::openat(
                    self.raw(),
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(errno());
            }
            Ok(SecureDir {
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
            })
        }

        /// `unlinkat(AT_REMOVEDIR)` an (empty) sub-directory. Used by the reaper
        /// to reclaim shard dirs left empty after their entries were evicted.
        pub fn remove_dir(&self, name: &str) -> io::Result<()> {
            let c = component(name)?;
            if unsafe { libc::unlinkat(self.raw(), c.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
                return Err(errno());
            }
            Ok(())
        }

        /// Create a fresh file (O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600) by a single
        /// component relative to this dir. Fails rather than follow a symlink or
        /// truncate an existing file.
        pub fn create_new(&self, name: &str) -> io::Result<File> {
            let c = component(name)?;
            let fd = unsafe {
                libc::openat(
                    self.raw(),
                    c.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(errno());
            }
            Ok(unsafe { File::from_raw_fd(fd) })
        }

        /// Open an existing file for reading (O_NOFOLLOW) by a single component.
        pub fn open_read(&self, name: &str) -> io::Result<File> {
            let c = component(name)?;
            let fd = unsafe {
                libc::openat(
                    self.raw(),
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(errno());
            }
            Ok(unsafe { File::from_raw_fd(fd) })
        }

        /// `renameat` within this directory (both names are single components).
        pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            let (f, t) = (component(from)?, component(to)?);
            if unsafe { libc::renameat(self.raw(), f.as_ptr(), self.raw(), t.as_ptr()) } != 0 {
                return Err(errno());
            }
            Ok(())
        }

        /// `unlinkat` a file within this directory.
        pub fn remove(&self, name: &str) -> io::Result<()> {
            let c = component(name)?;
            if unsafe { libc::unlinkat(self.raw(), c.as_ptr(), 0) } != 0 {
                return Err(errno());
            }
            Ok(())
        }

        /// fsync this directory (durability for a preceding rename/unlink).
        pub fn sync(&self) -> io::Result<()> {
            if unsafe { libc::fsync(self.raw()) } != 0 {
                return Err(errno());
            }
            Ok(())
        }

        /// List entry names (one directory level). Uses a dup'd fd because
        /// `fdopendir` takes ownership of the fd it's given.
        pub fn entries(&self) -> io::Result<Vec<String>> {
            let dupfd = unsafe { libc::dup(self.raw()) };
            if dupfd < 0 {
                return Err(errno());
            }
            let dirp = unsafe { libc::fdopendir(dupfd) };
            if dirp.is_null() {
                unsafe { libc::close(dupfd) };
                return Err(errno());
            }
            unsafe { libc::rewinddir(dirp) };
            let mut out = Vec::new();
            loop {
                let ent = unsafe { libc::readdir(dirp) };
                if ent.is_null() {
                    break;
                }
                let name_ptr = unsafe { (*ent).d_name.as_ptr() };
                let bytes = unsafe { std::ffi::CStr::from_ptr(name_ptr) }.to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                out.push(String::from_utf8_lossy(bytes).into_owned());
            }
            unsafe { libc::closedir(dirp) }; // also closes dupfd
            Ok(out)
        }

        /// fstatat (no-follow) a single component → (is_dir, is_symlink, len, mtime).
        pub fn stat(&self, name: &str) -> io::Result<(bool, bool, u64, std::time::SystemTime)> {
            let c = component(name)?;
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatat(self.raw(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) }
                != 0
            {
                return Err(errno());
            }
            let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
            let is_link = (st.st_mode & libc::S_IFMT) == libc::S_IFLNK;
            let mtime = std::time::UNIX_EPOCH
                + std::time::Duration::new(
                    st.st_mtime.max(0) as u64,
                    st.st_mtime_nsec.max(0) as u32,
                );
            Ok((is_dir, is_link, st.st_size.max(0) as u64, mtime))
        }
    }

    /// Read-only validation for `--check`: NEVER creates or chmods. If the dir
    /// exists it must be a non-symlink directory owned by the running uid;
    /// otherwise it's fine (startup will create it). Also rejects a symlinked
    /// final component (the attack shape).
    pub fn validate(path: &str) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        match std::fs::symlink_metadata(path) {
            Ok(md) => {
                if md.file_type().is_symlink() {
                    return Err(format!(
                        "{path}: is a symlink; refusing to store files here"
                    ));
                }
                if !md.is_dir() {
                    return Err(format!("{path}: exists but is not a directory"));
                }
                let euid = unsafe { libc::geteuid() };
                if md.uid() != euid {
                    return Err(format!(
                        "{path}: owned by uid {} but sluice runs as uid {euid}",
                        md.uid()
                    ));
                }
                Ok(())
            }
            // ONLY a genuine "not found" is OK (startup will create it 0700).
            // Any other error — ENOTDIR (a path component is a file), EACCES
            // (unreadable ancestor), ELOOP (symlink loop) — is a real problem
            // that would fail at startup, so it must fail `--check` too, not be
            // treated as "doesn't exist yet" (a previous fail-open bug).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{path}: {e}")),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Read, Write};
        use std::os::unix::fs::PermissionsExt;

        fn tmpbase(tag: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir().join(format!("sluice-sd-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        }

        #[test]
        fn provision_creates_nested_locks_mode_and_rejects_dotdot() {
            let base = tmpbase("prov");
            // Provision creates a DEEP nested path component-by-component.
            let deep = base.join("a/b/c/cache");
            let sd = SecureDir::provision(deep.to_str().unwrap()).unwrap();
            assert!(deep.is_dir(), "nested path must be created");
            assert_eq!(
                std::fs::metadata(&deep).unwrap().permissions().mode() & 0o7777,
                0o700,
                "final dir locked to 0700"
            );
            drop(sd);
            // Re-provisioning an existing 0777 dir tightens it to 0700.
            let loose = base.join("loose");
            std::fs::create_dir(&loose).unwrap();
            std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
            SecureDir::provision(loose.to_str().unwrap()).unwrap();
            assert_eq!(
                std::fs::metadata(&loose).unwrap().permissions().mode() & 0o7777,
                0o700
            );
            // `..` in the path is refused (can't walk upward out of the tree).
            assert!(SecureDir::provision(base.join("x/../y").to_str().unwrap()).is_err());
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn provision_follows_self_owned_symlink_component_but_would_reject_foreign() {
            // The parent-symlink TOCTOU fix walks each component with O_NOFOLLOW
            // and accepts a symlink component ONLY if the link is owned by root
            // or us. We can't create a foreign-owned symlink without root, so we
            // assert the TRUSTED path (a self-owned symlink IS followed — needed
            // for real system symlinks like macOS /var → private/var, which every
            // other provision test here already traverses). The foreign-owned
            // rejection is exercised by the reviewer's cross-UID test + the
            // `st_uid == 0 || st_uid == euid` gate in `open_or_make_dir`.
            let base = tmpbase("symparent");
            let realparent = base.join("realparent");
            std::fs::create_dir(&realparent).unwrap();
            let linkparent = base.join("linkparent");
            std::os::unix::fs::symlink(&realparent, &linkparent).unwrap(); // owned by us
            let sd = SecureDir::provision(linkparent.join("cache").to_str().unwrap())
                .expect("a self-owned symlink component is trusted and followed");
            drop(sd);
            // The real dir behind the trusted link now holds the pinned cache dir.
            assert!(realparent.join("cache").is_dir());
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn openat_ops_refuse_symlinked_components() {
            let base = tmpbase("ops");
            let root = base.join("root");
            std::fs::create_dir(&root).unwrap();
            let sd = SecureDir::provision(root.to_str().unwrap()).unwrap();

            // create_new + read round-trips within the pinned dir.
            {
                let mut f = sd.create_new("a.pem").unwrap();
                f.write_all(b"hi").unwrap();
            }
            let mut buf = String::new();
            sd.open_read("a.pem")
                .unwrap()
                .read_to_string(&mut buf)
                .unwrap();
            assert_eq!(buf, "hi");

            // A symlink planted for the target name is not followed on read…
            let victim = base.join("victim");
            std::fs::write(&victim, b"SECRET").unwrap();
            std::os::unix::fs::symlink(&victim, root.join("link.pem")).unwrap();
            assert!(sd.open_read("link.pem").is_err(), "must not follow symlink");
            // …and create_new can't clobber through it either.
            assert!(sd.create_new("link.pem").is_err());
            assert_eq!(std::fs::read(&victim).unwrap(), b"SECRET");

            // `..` / separators are rejected as components.
            assert!(sd.create_new("../escape").is_err());
            assert!(sd.open_read("a/b").is_err());
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn validate_is_read_only() {
            let base = tmpbase("val");
            let missing = base.join("nope");
            // Missing dir validates OK and is NOT created (read-only).
            validate(missing.to_str().unwrap()).unwrap();
            assert!(!missing.exists(), "validate must not create the dir");
            // A loose-mode existing owned dir validates without being chmod'd.
            let loose = base.join("loose");
            std::fs::create_dir(&loose).unwrap();
            std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
            validate(loose.to_str().unwrap()).unwrap();
            assert_eq!(
                std::fs::metadata(&loose).unwrap().permissions().mode() & 0o777,
                0o755,
                "validate must not chmod"
            );
            // A symlink is refused.
            let link = base.join("link");
            std::os::unix::fs::symlink(&loose, &link).unwrap();
            assert!(validate(link.to_str().unwrap()).is_err());
            // FAIL-OPEN regression: a path whose ancestor is a regular FILE
            // returns ENOTDIR, which must be an ERROR (it would fail at startup),
            // NOT silently treated as "doesn't exist yet, ok".
            let afile = base.join("afile");
            std::fs::write(&afile, b"x").unwrap();
            let under_file = afile.join("cache");
            assert!(
                validate(under_file.to_str().unwrap()).is_err(),
                "ENOTDIR must fail --check, not fail-open"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }
}

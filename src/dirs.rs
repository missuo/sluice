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

        /// Startup: create `path` (0700) if missing, open it `O_NOFOLLOW`
        /// (refusing a symlinked final component), verify it's a directory owned
        /// by the running uid, and `fchmod` it to 0700 on the opened fd. Fails
        /// closed. Parent-path components are followed here (an admin may
        /// legitimately symlink `/var/lib` → …); the returned fd then pins the
        /// resolved inode so nothing below can be re-routed later.
        pub fn provision(path: &str) -> Result<SecureDir, String> {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt};
            let _ = std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path); // ok if it already exists — verified below
            let cpath = CString::new(path.as_bytes()).map_err(|_| "path has NUL".to_string())?;
            // O_NOFOLLOW: a symlink AT `path` is refused outright.
            let fd = unsafe {
                libc::open(
                    cpath.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(format!("{path}: {}", errno()));
            }
            let dir = unsafe { OwnedFd::from_raw_fd(fd) };
            // fstat the OPEN fd (not the path) → no TOCTOU.
            let md = File::from(dir.try_clone().map_err(|e| e.to_string())?)
                .metadata()
                .map_err(|e| e.to_string())?;
            if !md.is_dir() {
                return Err(format!("{path}: not a directory"));
            }
            let euid = unsafe { libc::geteuid() };
            if md.uid() != euid {
                return Err(format!(
                    "{path}: owned by uid {} but sluice runs as uid {euid}",
                    md.uid()
                ));
            }
            if unsafe { libc::fchmod(dir.as_raw_fd(), 0o700) } != 0 {
                return Err(format!("{path}: cannot chmod 0700: {}", errno()));
            }
            Ok(SecureDir { fd: dir })
        }

        /// Open (creating if needed, 0700) a SUB-directory by a single component,
        /// relative to this dir's fd, `O_NOFOLLOW` — a symlinked component is
        /// refused. Used for the disk cache's two-level sharding.
        pub fn sub(&self, name: &str) -> io::Result<SecureDir> {
            let c = component(name)?;
            // mkdirat: ignore EEXIST, surface anything else.
            if unsafe { libc::mkdirat(self.raw(), c.as_ptr(), 0o700) } != 0 {
                let e = errno();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(e);
                }
            }
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
            // Missing is OK — startup will create it 0700. (A missing parent is
            // surfaced then, not here, so --check stays purely read-only.)
            Err(_) => Ok(()),
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
        fn provision_locks_mode_and_rejects_symlink() {
            let base = tmpbase("prov");
            let real = base.join("cache");
            std::fs::create_dir(&real).unwrap();
            std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o777)).unwrap();
            let sd = SecureDir::provision(real.to_str().unwrap()).unwrap();
            assert_eq!(
                std::fs::metadata(&real).unwrap().permissions().mode() & 0o7777,
                0o700
            );
            drop(sd);
            let link = base.join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert!(SecureDir::provision(link.to_str().unwrap()).is_err());
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
            let _ = std::fs::remove_dir_all(&base);
        }
    }
}

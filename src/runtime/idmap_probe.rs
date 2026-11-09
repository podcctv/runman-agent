//! Preflight the idmapped bind-mount operation used to start every guest.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nix::fcntl::OFlag;
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::waitpid;
use nix::unistd::{ForkResult, fork, pipe2};

use super::spec::{ID_BASE, ID_RANGE};
use super::sys;

/// Run the same open_tree/mount_setattr/move_mount sequence as the supervisor
/// on a temporary directory under `filesystem_dir`.
pub fn run(filesystem_dir: &Path) -> Result<()> {
    anyhow::ensure!(
        nix::unistd::Uid::effective().is_root(),
        "idmapped-mount probe must run as root"
    );
    let filesystem_dir = fs::canonicalize(filesystem_dir)
        .with_context(|| format!("resolve filesystem directory {}", filesystem_dir.display()))?;
    anyhow::ensure!(
        filesystem_dir.is_dir(),
        "filesystem probe path is not a directory: {}",
        filesystem_dir.display()
    );

    // Keep the probe mount and any failed intermediate mount local to this
    // helper process; exiting the command releases the temporary mount tree.
    unshare(CloneFlags::CLONE_NEWNS).context("unshare mount namespace")?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("make probe mount namespace private")?;

    let scratch = ScratchDir::create(&filesystem_dir)?;
    let source = scratch.0.join("source");
    let target = scratch.0.join("target");
    fs::create_dir(&source)?;
    fs::create_dir(&target)?;

    let result = probe_mount(&source, &target);
    if result.is_err() {
        let _ = sys::umount_if_mounted(&target);
    } else {
        sys::umount_if_mounted(&target).context("unmount idmapped probe")?;
    }
    result?;
    println!("idmapped bind-mount probe passed on {}", filesystem_dir.display());
    Ok(())
}

fn probe_mount(source: &Path, target: &Path) -> Result<()> {
    let (ready_read, ready_write) = pipe2(OFlag::O_CLOEXEC)?;
    let (release_read, release_write) = pipe2(OFlag::O_CLOEXEC)?;

    // This hidden helper is entered before Tokio starts, so fork is safe.
    match unsafe { fork() }.context("fork user-namespace probe")? {
        ForkResult::Child => child_userns(ready_read, ready_write, release_read, release_write),
        ForkResult::Parent { child } => {
            drop((ready_write, release_read));
            let mut ready = File::from(ready_read);
            let mut release = File::from(release_write);
            let mut signal = [0u8; 1];
            let result = (|| -> Result<()> {
                ready
                    .read_exact(&mut signal)
                    .context("user-namespace probe exited before creating its namespace")?;
                anyhow::ensure!(
                    signal[0] == b'U',
                    "user-namespace probe returned an invalid status"
                );

                let map = format!("0 {ID_BASE} {ID_RANGE}\n");
                fs::write(format!("/proc/{child}/uid_map"), &map)
                    .context("write probe uid_map")?;
                fs::write(format!("/proc/{child}/gid_map"), &map)
                    .context("write probe gid_map")?;
                let userns = File::open(format!("/proc/{child}/ns/user"))
                    .context("open probe user namespace")?;
                sys::idmapped_bind(source, target, &userns)
                    .with_context(|| format!("idmapped bind mount for {}", source.display()))?;
                Ok(())
            })();

            if result.is_ok() && release.write_all(b"X").is_ok() {
                // The child is released and will be reaped below.
            } else {
                let _ = kill(child, Signal::SIGKILL);
            }
            let _ = waitpid(child, None);
            result
        }
    }
}

fn child_userns(
    ready_read: OwnedFd,
    ready_write: OwnedFd,
    release_read: OwnedFd,
    release_write: OwnedFd,
) -> ! {
    drop((ready_read, release_write));
    let mut ready = File::from(ready_write);
    let mut release = File::from(release_read);
    if let Err(error) = unshare(CloneFlags::CLONE_NEWUSER) {
        eprintln!("create probe user namespace: {error}");
        unsafe { libc::_exit(1) }
    }
    if let Err(error) = ready.write_all(b"U") {
        eprintln!("signal probe user namespace: {error}");
        unsafe { libc::_exit(1) }
    }
    let mut signal = [0u8; 1];
    if let Err(error) = release.read_exact(&mut signal) {
        eprintln!("wait for idmapped mount probe: {error}");
        unsafe { libc::_exit(1) }
    }
    unsafe { libc::_exit(0) }
}

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn create(parent: &Path) -> Result<Self> {
        let pid = std::process::id();
        for suffix in 0..32 {
            let path = parent.join(format!(".runman-idmap-probe-{pid}-{suffix}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    if let Err(error) =
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    {
                        let _ = fs::remove_dir(&path);
                        return Err(error).context("secure idmapped-mount probe directory");
                    }
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error).context("create idmapped-mount probe directory"),
            }
        }
        bail!("could not allocate a unique idmapped-mount probe directory")
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

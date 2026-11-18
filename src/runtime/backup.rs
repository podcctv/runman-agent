//! Local, root-owned backups of stopped system containers.

use std::fs::{self, DirBuilder, File};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use super::*;
use crate::model::{InstanceBackup, RestoredForward, RestoredInstance};

const FORMAT: u32 = 1;
const PAYLOAD: &str = "payload.tar";
const MANIFEST: &str = "manifest.json";
const PENDING_FORWARDS: &str = "restore-forwards.json";

#[derive(Serialize, Deserialize)]
struct Manifest {
    format: u32,
    architecture: String,
    created: u64,
    source: Record,
    sha256: String,
    forwards: Vec<StoredForward>,
}

impl Manifest {
    fn read(dir: &Path) -> Result<Self> {
        let manifest: Self = serde_json::from_slice(&fs::read(dir.join(MANIFEST))?)?;
        ensure!(manifest.format == FORMAT, "unsupported backup version");
        Ok(manifest)
    }

    fn summary(&self, id: &VmId) -> InstanceBackup {
        InstanceBackup {
            id: id.to_string(),
            source_id: self.source.id.clone(),
            hostname: self.source.hostname.clone(),
            created: self.created,
        }
    }
}

struct Staging(PathBuf);

impl Staging {
    fn new(parent: &Path) -> Result<Self> {
        let path = parent.join(format!(".partial-{}", uuid::Uuid::new_v4()));
        DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn digest(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 128 * 1024];
    loop {
        let count = file.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn mount_worker(script: &str) -> Command {
    // The mount belongs to the helper, so even a killed handler cannot leave a
    // mount in staging or make staging cleanup traverse the guest filesystem.
    let mut worker = Command::new("unshare");
    worker.kill_on_drop(true).env_remove("TAR_OPTIONS").args([
        "--mount",
        "--propagation",
        "private",
        "--fork",
        "--kill-child",
        "--",
        "bash",
        "-eu",
        "-c",
        script,
        "runman-backup",
    ]);
    worker
}

impl Runtime {
    fn backup_dir(&self) -> PathBuf {
        self.data.join("backups")
    }

    pub(super) fn list_backups(&self) -> Result<Vec<InstanceBackup>> {
        let entries = match fs::read_dir(self.backup_dir()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut backups = Vec::new();
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let Ok(id) = VmId::parse(&entry.file_name().to_string_lossy()) else {
                continue;
            };
            match Manifest::read(&entry.path()) {
                Ok(manifest) => backups.push(manifest.summary(&id)),
                Err(error) => warn!("backup {id}: {error:#}"),
            }
        }
        backups.sort_by_key(|backup| std::cmp::Reverse(backup.created));
        Ok(backups)
    }

    pub(super) async fn backup_stopped_instance(&self, id: &VmId) -> Result<InstanceBackup> {
        let _instance = self.lock_vm(id.as_str()).await;
        let source = self.require(id)?;
        let spec = self.run_spec(&source);
        ensure!(
            !source.builder
                && source.desired == Desired::Stopped
                && !self.is_active(id.as_str()).await
                && !sys::is_mountpoint(&spec.mnt_disk()),
            "stop the instance before backing it up"
        );
        let parent = self.backup_dir();
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&parent)?;
        let staging = Staging::new(&parent)?;
        let archive = staging.0.join(PAYLOAD);
        let base = source
            .lower
            .parent()
            .context("image has no parent directory")?;
        ensure!(
            source.lower == base.join("rootfs"),
            "invalid image rootfs path"
        );
        let forwards = self
            .forwards
            .lock()
            .await
            .iter()
            .filter(|forward| &forward.vm_id == id)
            .map(|forward| StoredForward {
                vm_id: id.to_string(),
                proto: forward.proto.as_str().into(),
                host_port: forward.host_port,
                guest_port: forward.guest_port,
                description: forward.description.clone(),
            })
            .collect();
        let mount = staging.0.join("upper");
        fs::create_dir(&mount)?;
        run(mount_worker(
            r#"
mount -t ext4 -o loop,ro,noload,nodev "$1" "$2"
exec tar --numeric-owner --xattrs --xattrs-include='*' --xattrs-exclude=user.overlay.origin \
    --acls --sparse --format=pax -cf "$3" -C "$2" up -C "$4" rootfs
"#,
        )
        .arg(spec.disk_image())
        .arg(&mount)
        .arg(&archive)
        .arg(base))
        .await
        .context("archive instance disk and image")?;
        fs::remove_dir(mount)?;
        File::open(&archive)?.sync_all()?;
        let manifest = Manifest {
            format: FORMAT,
            architecture: std::env::consts::ARCH.into(),
            created: unix_now(),
            source,
            sha256: digest(&archive).await?,
            forwards,
        };
        fsutil::write_atomic(&staging.0.join(MANIFEST), &serde_json::to_vec(&manifest)?)?;
        File::open(&staging.0)?.sync_all()?;
        let backup_id = VmId::parse(&uuid::Uuid::new_v4().to_string())?;
        fs::rename(&staging.0, parent.join(backup_id.as_str()))?;
        File::open(parent)?.sync_all()?;
        Ok(manifest.summary(&backup_id))
    }

    pub(super) async fn restore_stopped_instance(
        &self,
        backup_id: &VmId,
    ) -> Result<RestoredInstance> {
        let backup = self.backup_dir().join(backup_id.as_str());
        ensure!(
            fs::symlink_metadata(&backup)?.is_dir(),
            "invalid backup directory"
        );
        let manifest = Manifest::read(&backup)?;
        ensure!(
            manifest.architecture == std::env::consts::ARCH,
            "backup architecture differs from this node"
        );
        let archive = backup.join(PAYLOAD);
        ensure!(
            fs::symlink_metadata(&archive)?.is_file(),
            "invalid backup payload"
        );
        ensure!(
            digest(&archive).await? == manifest.sha256,
            "backup checksum mismatch"
        );
        let instances = self.data.join("instances");
        let staging = Staging::new(&instances)?;
        let mut record = manifest.source;
        let disk = staging.0.join("disk.img");
        let id = VmId::parse(&uuid::Uuid::new_v4().to_string())?;
        let _instance = self.lock_vm(id.as_str()).await;
        let target = self.dir(id.as_str());
        for path in ["mnt", "mnt/disk", "mnt/lower", "mnt/upper", "mnt/rootfs"] {
            mkdir_private(&staging.0.join(path))?;
        }
        format_instance_disk(&disk, record.disk_gb).await?;
        run(mount_worker(
            r#"
mount -t ext4 -o loop,nodev "$1" "$2"
tar_args=(--numeric-owner --same-owner --same-permissions --xattrs --xattrs-include='*' --acls)
tar "${tar_args[@]}" -xf "$3" -C "$2" up
mkdir "$2/wk"
tar "${tar_args[@]}" -xf "$3" -C "$4" rootfs
umount "$2"
"#,
        )
        .arg(&disk)
        .arg(staging.0.join("mnt/disk"))
        .arg(&archive)
        .arg(&staging.0))
        .await
        .context("extract instance backup")?;
        ensure!(
            fs::symlink_metadata(staging.0.join("rootfs"))?.is_dir(),
            "backup rootfs is not a directory"
        );
        File::open(&disk)?.sync_all()?;
        {
            let _allocation = self.alloc.lock().unwrap();
            ensure!(!target.exists(), "restore destination already exists");
            record.id = id.to_string();
            record.generation = uuid::Uuid::new_v4().to_string();
            record.idx = self.allocate_idx()?;
            record.addrs = self.net.addrs_for(record.idx)?;
            record.lower = target.join("rootfs");
            record.desired = Desired::Stopped;
            record.builder = false;
            record.network_quarantined = false;
            record.network_pending = true;
            record.created = unix_now();
            fsutil::write_atomic(
                &staging.0.join("instance.json"),
                &serde_json::to_vec(&record)?,
            )?;
            fsutil::write_atomic(
                &staging.0.join("runtime.json"),
                &serde_json::to_vec(&self.run_spec(&record))?,
            )?;
            fsutil::write_atomic(
                &staging.0.join(PENDING_FORWARDS),
                &serde_json::to_vec(&manifest.forwards)?,
            )?;
            // The container userns must be able to traverse the instance path.
            mkdir_private(&staging.0)?;
            File::open(&staging.0)?.sync_all()?;
            fs::rename(&staging.0, &target)?;
            File::open(&instances)?.sync_all()?;
        }
        let forwards = self.finish_restore_forwards(&id).await.with_context(|| {
            format!("restored instance {id} is stopped; could not apply its ports")
        })?;
        Ok(RestoredInstance { id, forwards })
    }

    pub(super) async fn finish_restore_forwards(&self, id: &VmId) -> Result<Vec<RestoredForward>> {
        let pending = self.dir(id.as_str()).join(PENDING_FORWARDS);
        let data = match fs::read(&pending) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let requested: Vec<StoredForward> = serde_json::from_slice(&data)?;
        let mut forwards = self.forwards.lock().await;
        let mut next = forwards
            .iter()
            .filter(|forward| &forward.vm_id != id)
            .cloned()
            .collect::<Vec<_>>();
        let mut restored = Vec::with_capacity(requested.len());
        for rule in requested {
            let proto = match rule.proto.as_str() {
                "tcp" => L4Proto::Tcp,
                "udp" => L4Proto::Udp,
                _ => bail!("unsupported backup port protocol"),
            };
            let available = |port| {
                !next.iter().any(|f| f.proto == proto && f.host_port == port)
                    && !net::host_listening(proto, port)
            };
            ensure!(
                rule.host_port > 0 && rule.guest_port > 0,
                "invalid backup port"
            );
            let port = if available(rule.host_port) {
                rule.host_port
            } else {
                let mut candidates = AUTO_PORTS;
                candidates
                    .find(|port| available(*port))
                    .context("no free host port")?
            };
            next.push(PortForward {
                vm_id: id.clone(),
                proto,
                host_port: port,
                guest_port: rule.guest_port,
                description: rule.description,
            });
            restored.push(RestoredForward {
                proto: rule.proto,
                previous_host_port: rule.host_port,
                host_port: port,
                guest_port: rule.guest_port,
            });
        }
        self.apply_network(&next).await?;
        if let Err(error) = self.save_forwards(&next) {
            let _ = self.apply_network(&forwards).await;
            return Err(error);
        }
        *forwards = next;
        File::open(&self.data)?.sync_all()?;
        fs::remove_file(pending)?;
        Ok(restored)
    }

    pub(super) async fn prepare_restored_network(&self, id: &VmId) -> Result<()> {
        self.finish_restore_forwards(id).await?;
        let mut record = self.require(id)?;
        if record.network_pending {
            self.update_instance_network(&record).await?;
            record.network_pending = false;
            self.save(&record)?;
        }
        Ok(())
    }
}

//! System-container runtime: implements [`Instances`] and [`PortForwards`] on
//! top of transient systemd units running [`supervisor`].
//!
//! Per instance (`<data>/instances/<id>/`):
//! - `instance.json` — the record (resources, image, addresses, desired state);
//! - `runtime.json`  — the [`RunSpec`] handed to the supervisor;
//! - `disk.img`      — sparse ext4 holding the overlay upper/work dirs, sized
//!   to the plan's disk so the limit is a real filesystem size;
//! - `traffic.json`  — accumulated traffic counters;
//! - `console.log`   — the instance console.
//!
//! Port forwards live in `<data>/portforwards.json`.

pub mod attach;
pub mod build;
pub mod customize;
pub mod exec;
pub mod fsutil;
pub mod idmap_probe;
pub mod image;
pub mod monitor;
pub mod net;
pub mod seccomp;
pub mod spec;
pub mod supervisor;
pub mod sys;
pub mod wg;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

use crate::backend::{ConsoleIo, Instances, PortForwards, WgBindings};
use crate::config::{self, Config, NetworkConfig};
use crate::model::{ConsoleSize, InstanceDetails, InstanceSpec, L4Proto, PortForward, VmId};
use crate::proto;
use crate::traffic::{Schedule, Traffic};
use exec::ExecTarget;
use fsutil::{RootFs, mkdir_private};
use image::{ImageStore, run};
use net::{Addrs, Forward, Net, Port};
use spec::{ID_BASE, ID_RANGE, NetSpec, RunSpec, unit_cgroup, unit_name};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

const RUN_ROOT: &str = "/run/runman-agent";
const START_TIMEOUT: Duration = Duration::from_secs(15);
/// Highest instance index so the UID ranges stay below 2^32.
const MAX_IDX: u32 = (u32::MAX - ID_BASE) / ID_RANGE - 1;
/// Range for automatically chosen host ports.
const AUTO_PORTS: std::ops::Range<u16> = 20000..60000;

pub struct Options {
    pub data_dir: PathBuf,
    pub image_base_url: String,
    pub tun: bool,
    pub network: NetworkConfig,
    pub traffic: Schedule,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoMigrationManifest {
    schema: u32,
    source_backend: String,
    instances: Vec<GoMigrationInstance>,
    port_forwards: Vec<GoMigrationForward>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoMigrationInstance {
    vm_id: String,
    cpu: u32,
    ram_mb: u64,
    disk_gb: u64,
    bandwidth_mbps: u32,
    os_image: String,
    root_password: String,
    was_running: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoMigrationForward {
    vm_id: String,
    protocol: String,
    host_port: u16,
    guest_port: u16,
    description: String,
}

impl Options {
    pub fn from_config(c: &Config) -> Self {
        Self {
            data_dir: c.data_dir.clone(),
            image_base_url: c.image_base_url.clone(),
            tun: c.tun,
            network: c.network.clone(),
            traffic: c.traffic_schedule(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Desired {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    id: String,
    /// Changes whenever an instance is replaced, so external temporary
    /// controls cannot silently follow a new workload with the same VM ID.
    #[serde(default)]
    generation: String,
    idx: u32,
    cpu: u32,
    ram_mb: u64,
    disk_gb: u64,
    bandwidth_mbps: u32,
    os_image: String,
    /// Image template this instance's overlay was built on.
    lower: PathBuf,
    stop_signal: String,
    hostname: String,
    addrs: Addrs,
    desired: Desired,
    /// Watcher quarantine state is persistent and survives instance restart.
    #[serde(default)]
    network_quarantined: bool,
    /// Address record changed but the guest's static network config still
    /// needs to be rewritten. Retried on the next agent start after a crash.
    #[serde(default)]
    network_pending: bool,
    /// Temporary instance building a custom image: hidden from listings and
    /// heartbeats (the platform would delete it as an orphan).
    #[serde(default)]
    builder: bool,
    /// Unix time of the first create (kept across reinstalls); aligns
    /// traffic periods in `creation` reset mode. 0 in records of older
    /// agents until `init` fills it in.
    #[serde(default)]
    created: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredForward {
    vm_id: String,
    proto: String,
    host_port: u16,
    guest_port: u16,
    #[serde(default)]
    description: String,
}

pub struct Runtime {
    data: PathBuf,
    exe: PathBuf,
    images: ImageStore,
    tun: bool,
    net: Net,
    /// Traffic schedule in effect; its lock also serializes `traffic.json`
    /// writes against relabelling (see `traffic_schedule`).
    schedule: Mutex<Schedule>,
    /// Live configuration, for schedule changes made in the panel.
    config: Option<Arc<config::Store>>,
    /// Port forwards; the lock also serializes ruleset updates.
    forwards: tokio::sync::Mutex<Vec<PortForward>>,
    cpu_samples: Mutex<HashMap<String, (Instant, u64)>>,
    tunnels: tokio::sync::Mutex<wg::Tunnels>,
    /// Dedicated addresses per instance id (snapshot of `tunnels`, readable
    /// without its async lock).
    dedicated: Mutex<BTreeMap<String, Vec<IpAddr>>>,
    /// Instances whose in-instance network config still has to be updated.
    net_pending: Mutex<BTreeSet<String>>,
    /// Serializes operations on one instance (platform commands and WG sync
    /// both touch an instance's rootfs and unit).
    vm_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Serializes instance index allocation (see `create_locked`).
    alloc: Mutex<()>,
    /// Resource history (`metrics.db`) and the previous counter readings
    /// its rates are computed from.
    history: Arc<crate::history::History>,
    monitor_prev: Mutex<HashMap<String, monitor::Counters>>,
    builds: build::Builds,
}

impl Runtime {
    pub fn new(opts: Options) -> Result<Self> {
        let data_dir = &opts.data_dir;
        // Paths are embedded in overlayfs mount options.
        if data_dir
            .to_string_lossy()
            .contains([',', ':', '\\', ' ', '\n'])
            || !data_dir.is_absolute()
        {
            bail!("data_dir must be an absolute path without ',', ':', '\\' or whitespace");
        }
        mkdir_private(data_dir)?;
        mkdir_private(&data_dir.join("instances"))?;
        let forwards = load_forwards(&data_dir.join("portforwards.json"))?;
        let net = Net::from_config(&opts.network)?;
        let tunnels = wg::Tunnels::load(
            data_dir,
            &net.bridge,
            &opts.network.wg_prefix,
            opts.network.wg_table_base,
        )?;
        let dedicated = tunnels.addresses_by_vm();
        Ok(Self {
            data: data_dir.clone(),
            exe: std::env::current_exe()?,
            images: ImageStore::new(data_dir, &opts.image_base_url)?,
            tun: opts.tun,
            net,
            schedule: Mutex::new(opts.traffic),
            config: None,
            forwards: tokio::sync::Mutex::new(forwards),
            cpu_samples: Mutex::default(),
            tunnels: tokio::sync::Mutex::new(tunnels),
            dedicated: Mutex::new(dedicated),
            net_pending: Mutex::default(),
            vm_locks: Mutex::default(),
            alloc: Mutex::default(),
            history: Arc::new(crate::history::History::open(&data_dir.join("metrics.db"))?),
            monitor_prev: Mutex::default(),
            builds: build::Builds::new(&data_dir.join("image-builds"))?,
        })
    }

    async fn lock_vm(&self, id: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = self
            .vm_locks
            .lock()
            .unwrap()
            .entry(id.to_owned())
            .or_default()
            .clone();
        lock.lock_owned().await
    }

    fn dedicated_for(&self, id: &str) -> Vec<IpAddr> {
        self.dedicated
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .unwrap_or_default()
    }

    fn net_files(&self, rec: &Record) -> customize::NetFiles {
        customize::NetFiles {
            ipv4: rec.addrs.ipv4,
            prefix4: self.net.v4_prefix_len(),
            gateway4: self.net.gateway4(),
            ipv6: rec.addrs.ipv6,
            gateway6: self.net.gateway6(),
            dns: self.net.dns.clone(),
            extra: self.dedicated_for(&rec.id),
        }
    }

    /// Rewrite the instance's own network config (dedicated IPs changed) and
    /// apply it: live through its network manager, or on disk when stopped.
    async fn update_instance_network(&self, rec: &Record) -> Result<()> {
        let files = self.net_files(rec);
        if self.is_active(&rec.id).await {
            let script = customize::network_update_script(&files);
            self.exec_target(&rec.id)
                .run(&["sh", "-s"], script.as_bytes())
                .await
        } else {
            self.with_offline_rootfs(rec, false, move |root| {
                customize::write_network(root, &files)
            })
            .await
        }
    }

    /// Follow the traffic schedule of a live configuration.
    pub fn with_config(mut self, store: Arc<config::Store>) -> Self {
        self.config = Some(store);
        self
    }

    /// Binary that provides `__supervise`/`__exec` (default: this executable).
    pub fn with_helper(mut self, exe: PathBuf) -> Self {
        self.exe = exe;
        self
    }

    pub fn images(&self) -> &ImageStore {
        &self.images
    }

    /// Download new official image versions, then drop versions no instance
    /// is built on.
    pub async fn refresh_images(&self) {
        if let Err(e) = self.images.sync().await {
            warn!("image sync: {e:#}");
        }
        self.gc_images();
    }

    /// Drop image versions no instance is built on.
    pub fn gc_images(&self) {
        let _alloc = self.alloc.lock().unwrap();
        let in_use: Vec<PathBuf> = self
            .records()
            .map(|r| r.into_iter().map(|r| r.lower).collect())
            .unwrap_or_default();
        self.images.gc(&in_use);
    }

    /// Prepare host networking and start every instance that should be
    /// running (after boot or an agent upgrade).
    pub async fn init(&self) -> Result<()> {
        self.net.setup_host().await.context("host network setup")?;
        let inotify = std::fs::read_to_string("/proc/sys/fs/inotify/max_user_instances")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        if inotify < 8192 {
            // Every instance runs a full init; their inotify instances all
            // count against one host user, so the default (128) runs out
            // after a handful of instances.
            warn!(
                "fs.inotify.max_user_instances is {inotify}; instances will fail to start services. \
                 Re-run install.sh or set it to 65536 (/etc/sysctl.d/90-runman.conf)"
            );
        }
        if self
            .dedicated
            .lock()
            .unwrap()
            .values()
            .flatten()
            .any(IpAddr::is_ipv6)
        {
            self.net.enable_v6().await?;
        }

        // Reconcile persisted guest addresses with the current network config.
        // This migrates older generated addresses (or an earlier pool) while
        // retaining each instance's stable index. Preflight every slot before
        // writing any record so a pool that is too small fails without a
        // partial address migration.
        let address_updates: Vec<(Record, Addrs)> = self
            .records()?
            .into_iter()
            .filter(|r| !r.builder)
            .map(|rec| {
                let addrs = self.net.addrs_for(rec.idx)?;
                Ok((rec, addrs))
            })
            .collect::<Result<_>>()?;
        for (mut rec, addrs) in address_updates {
            if rec.addrs != addrs {
                rec.addrs = addrs;
                rec.network_pending = true;
                self.save(&rec)?;
            }
        }
        self.reconcile_network().await?;
        for mut rec in self.records()?.into_iter().filter(|r| r.network_pending) {
            self.update_instance_network(&rec)
                .await
                .with_context(|| format!("update network for instance {}", rec.id))?;
            rec.network_pending = false;
            self.save(&rec)?;
        }
        // Older records have no incarnation identity. Assign one before
        // exposing them to local control APIs.
        for mut rec in self
            .records()?
            .into_iter()
            .filter(|r| r.generation.is_empty())
        {
            rec.generation = uuid::Uuid::new_v4().to_string();
            self.save(&rec)?;
        }
        // Records of older agents have no creation time: take the instance
        // directory's (its birth time where the filesystem records one).
        for mut rec in self.records()?.into_iter().filter(|r| r.created == 0) {
            let meta = std::fs::metadata(self.dir(&rec.id))?;
            let born = meta.created().or_else(|_| meta.modified())?;
            rec.created = born
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or_else(|_| unix_now(), |d| d.as_secs());
            self.save(&rec)?;
        }
        // Builds do not survive a restart; drop their temporary instances.
        for rec in self.records()?.into_iter().filter(|r| r.builder) {
            let id = VmId::parse(&rec.id).expect("record ids are validated");
            warn!(
                "removing builder {} left by an interrupted image build",
                rec.id
            );
            if let Err(e) = self.delete(&id).await {
                warn!("remove builder {}: {e:#}", rec.id);
            }
        }
        for rec in self
            .records()?
            .into_iter()
            .filter(|r| r.desired == Desired::Running)
        {
            let id = VmId::parse(&rec.id).expect("record ids are validated");
            if let Err(e) = self.start(&id).await {
                warn!("autostart {}: {e:#}", rec.id);
            }
        }
        Ok(())
    }

    fn dir(&self, id: &str) -> PathBuf {
        self.data.join("instances").join(id)
    }

    fn run_spec(&self, rec: &Record) -> RunSpec {
        RunSpec {
            id: rec.id.clone(),
            dir: self.dir(&rec.id),
            lower: rec.lower.clone(),
            uid_base: ID_BASE + rec.idx * ID_RANGE,
            hostname: rec.hostname.clone(),
            stop_signal: rec.stop_signal.clone(),
            tun: self.tun,
            run_dir: Path::new(RUN_ROOT).join(&rec.id),
            cpus: rec.cpu,
            net: Some(NetSpec {
                host_if: self.net.host_if(rec.idx),
                bridge: self.net.bridge.clone(),
                mac: net::mac(rec.idx),
                bandwidth_mbps: rec.bandwidth_mbps,
                isolated: rec.network_quarantined,
            }),
        }
    }

    fn exec_target(&self, id: &str) -> ExecTarget {
        ExecTarget {
            exe: self.exe.clone(),
            pid_file: Path::new(RUN_ROOT).join(id).join("init.pid"),
            unit_cgroup: unit_cgroup(id),
        }
    }

    fn load(&self, id: &str) -> Result<Option<Record>> {
        match std::fs::read(self.dir(id).join("instance.json")) {
            Ok(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn require(&self, id: &VmId) -> Result<Record> {
        self.load(id.as_str())?
            .with_context(|| format!("instance {id} not found"))
    }

    fn save(&self, rec: &Record) -> Result<()> {
        let dir = self.dir(&rec.id);
        fsutil::write_atomic(&dir.join("instance.json"), &serde_json::to_vec_pretty(rec)?)?;
        fsutil::write_atomic(
            &dir.join("runtime.json"),
            &serde_json::to_vec_pretty(&self.run_spec(rec))?,
        )
    }

    fn records(&self) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(self.data.join("instances"))? {
            let name = entry?.file_name();
            let Some(name) = name.to_str() else { continue };
            if VmId::parse(name).is_err() {
                continue;
            }
            match self.load(name) {
                Ok(Some(rec)) => out.push(rec),
                Ok(None) => {}
                Err(e) => warn!("instance {name}: unreadable record: {e:#}"),
            }
        }
        Ok(out)
    }

    /// Resolve a local-control target against a live, Runman-owned instance.
    /// The generation value prevents a delayed policy from attaching to a
    /// replacement that reused the same platform VM UUID.
    pub async fn connlimit_target(&self, raw_id: &str) -> Result<crate::connlimit::Target> {
        let id = VmId::parse(raw_id)?;
        let Some(rec) = self.load(id.as_str())? else {
            return Ok(crate::connlimit::Target {
                managed: false,
                running: false,
                instance_id: String::new(),
                ips: Vec::new(),
            });
        };
        if rec.builder {
            return Ok(crate::connlimit::Target {
                managed: false,
                running: false,
                instance_id: String::new(),
                ips: Vec::new(),
            });
        }
        let dedicated = self
            .dedicated
            .lock()
            .unwrap()
            .get(id.as_str())
            .cloned()
            .unwrap_or_default();
        let mut ips = vec![rec.addrs.ipv4.to_string()];
        if let Some(ip) = rec.addrs.ipv6 {
            ips.push(ip.to_string());
        }
        ips.extend(dedicated.into_iter().map(|ip| ip.to_string()));
        ips.sort();
        ips.dedup();
        Ok(crate::connlimit::Target {
            managed: true,
            running: rec.desired == Desired::Running && self.is_active(id.as_str()).await,
            instance_id: rec.generation,
            ips,
        })
    }

    /// Execute a bounded guest command requested by the local, root-only
    /// Watcher socket. UUID plus generation prevents work from following a
    /// replaced instance; the VM lock serializes it with lifecycle changes.
    pub async fn watcher_exec(
        &self,
        raw_id: &str,
        expected_generation: &str,
        project: &str,
        command: &str,
        timeout_seconds: u64,
    ) -> Result<(i32, String, String)> {
        anyhow::ensure!(
            project == "default",
            "only the default project is supported"
        );
        anyhow::ensure!(
            !command.is_empty() && command.len() <= 64 * 1024 && !command.contains('\0'),
            "guest command is empty or exceeds 64 KiB"
        );
        anyhow::ensure!(
            (1..=90).contains(&timeout_seconds),
            "guest command timeout must be between 1 and 90 seconds"
        );
        let id = VmId::parse(raw_id)?;
        let _guard = self.lock_vm(id.as_str()).await;
        let Some(rec) = self.load(id.as_str())? else {
            bail!("Runman instance is not managed");
        };
        anyhow::ensure!(!rec.builder, "temporary image builders are not addressable");
        anyhow::ensure!(
            !expected_generation.is_empty() && rec.generation == expected_generation,
            "Runman instance generation changed"
        );
        anyhow::ensure!(
            rec.desired == Desired::Running && self.is_active(id.as_str()).await,
            "Runman instance is not running"
        );

        let (code, stdout, stderr) = self
            .exec_target(id.as_str())
            .run_capture(
                &["/bin/sh", "-s"],
                command.as_bytes(),
                Duration::from_secs(timeout_seconds),
                64 * 1024,
            )
            .await?;
        Ok((
            code,
            String::from_utf8_lossy(&stdout).into_owned(),
            String::from_utf8_lossy(&stderr).into_owned(),
        ))
    }

    /// Stop only the same, still-overloaded Runman generation. The VM lock
    /// serializes the identity check, final procfs sample, desired-state
    /// update and systemd stop against Runman lifecycle operations.
    pub async fn watcher_stop_overload(
        &self,
        raw_id: &str,
        expected_generation: &str,
        project: &str,
        threshold: u32,
        metric_tcp_active: bool,
    ) -> Result<(String, u64)> {
        anyhow::ensure!(
            project == "default",
            "only the default project is supported"
        );
        anyhow::ensure!(
            (1..=10_000_000).contains(&threshold),
            "connection stop threshold is invalid"
        );
        let generation = uuid::Uuid::parse_str(expected_generation)
            .context("invalid Runman instance generation")?;
        anyhow::ensure!(
            generation.get_version_num() == 4 && generation.to_string() == expected_generation,
            "Runman instance generation must be a canonical UUID v4"
        );
        let id = VmId::parse(raw_id)?;
        let _guard = self.lock_vm(id.as_str()).await;
        let Some(rec) = self.load(id.as_str())? else {
            bail!("Runman instance is not managed");
        };
        anyhow::ensure!(!rec.builder, "temporary image builders are not addressable");
        anyhow::ensure!(
            rec.generation == expected_generation,
            "Runman instance generation changed"
        );
        anyhow::ensure!(
            rec.desired == Desired::Running && self.is_active(id.as_str()).await,
            "Runman instance is not running"
        );
        let pid_path = self.run_spec(&rec).init_pid_file();
        let pid = std::fs::read_to_string(&pid_path)
            .context("Runman init PID is unavailable")?
            .trim()
            .parse::<i32>()
            .context("Runman init PID is invalid")?;
        anyhow::ensure!(pid > 1, "Runman init PID is invalid");
        let (established, pending, time_wait, udp_sockets) = monitor::watcher_tcp_counts(pid)
            .context("fresh Runman connection tables are unavailable")?;
        let current_connections = if metric_tcp_active {
            established.saturating_add(pending)
        } else {
            established
                .saturating_add(pending)
                .saturating_add(time_wait)
                .saturating_add(udp_sockets)
        };
        anyhow::ensure!(
            current_connections > u64::from(threshold),
            "Runman connection load recovered below the stop threshold"
        );
        let current_pid = std::fs::read_to_string(&pid_path)
            .ok()
            .and_then(|raw| raw.trim().parse::<i32>().ok());
        anyhow::ensure!(
            current_pid == Some(pid) && self.is_active(id.as_str()).await,
            "Runman process changed during the final connection check"
        );
        self.set_desired(&id, Desired::Stopped)?;
        self.halt(id.as_str(), false).await?;
        Ok((rec.generation, current_connections))
    }

    /// Apply or read a reversible per-instance network quarantine. The
    /// persistent record is written before toggling the host veth so restarts
    /// and crash recovery follow the same fail-closed desired state.
    pub async fn watcher_network_quarantine(
        &self,
        raw_id: &str,
        expected_generation: &str,
        project: &str,
        action: &str,
    ) -> Result<(String, bool, bool, bool, i32)> {
        anyhow::ensure!(
            project == "default",
            "only the default project is supported"
        );
        anyhow::ensure!(
            !expected_generation.is_empty() && expected_generation.len() <= 200,
            "Runman instance generation is required"
        );
        anyhow::ensure!(
            matches!(action, "inspect" | "isolate" | "release" | "replacement"),
            "unsupported Runman network quarantine action"
        );
        let id = VmId::parse(raw_id)?;
        let _guard = self.lock_vm(id.as_str()).await;
        let Some(mut rec) = self.load(id.as_str())? else {
            bail!("Runman instance is not managed");
        };
        anyhow::ensure!(!rec.builder, "temporary image builders are not addressable");
        if action != "replacement" {
            anyhow::ensure!(
                rec.generation == expected_generation,
                "Runman instance generation changed"
            );
        }

        let running = rec.desired == Desired::Running && self.is_active(id.as_str()).await;
        let host_if = self.net.host_if(rec.idx);
        let mut interface_up = if running {
            attach::host_link_up(&host_if)?
        } else {
            false
        };

        match action {
            "inspect" | "replacement" => {
                if running {
                    anyhow::ensure!(
                        rec.network_quarantined == !interface_up,
                        "Runman network link state does not match its quarantine record"
                    );
                }
            }
            "isolate" => {
                anyhow::ensure!(running, "Runman instance is not running");
                if !rec.network_quarantined {
                    anyhow::ensure!(
                        interface_up,
                        "Runman interface is down without a quarantine record"
                    );
                    rec.network_quarantined = true;
                    self.save(&rec)?;
                }
                if interface_up {
                    attach::set_host_link_up(&host_if, false)?;
                }
                interface_up = false;
            }
            "release" => {
                anyhow::ensure!(
                    rec.network_quarantined,
                    "Runman instance has no active quarantine"
                );
                if running {
                    anyhow::ensure!(
                        !interface_up,
                        "Runman quarantine link state changed; refused to re-enable it"
                    );
                }
                rec.network_quarantined = false;
                self.save(&rec)?;
                if running {
                    attach::set_host_link_up(&host_if, true)?;
                    interface_up = true;
                }
            }
            _ => unreachable!("action was validated above"),
        }
        let pid = std::fs::read_to_string(self.run_spec(&rec).init_pid_file())
            .ok()
            .and_then(|raw| raw.trim().parse::<i32>().ok())
            .filter(|pid| *pid > 1)
            .unwrap_or(0);
        Ok((
            rec.generation,
            rec.network_quarantined,
            interface_up,
            running,
            pid,
        ))
    }

    /// Read-only inventory contract for Podman Watcher. Runman remains a
    /// distinct runtime; metrics include their own freshness and generation.
    pub async fn watcher_inventory(&self) -> Result<serde_json::Value> {
        let now = unix_now();
        let schedule = *self.traffic_schedule();
        let history = self.history.clone();
        let recent_usage = tokio::task::spawn_blocking(move || history.usage(180, now))
            .await
            .ok()
            .and_then(|result| result.ok())
            .unwrap_or_default();
        let usage_by_vm: HashMap<_, _> = recent_usage
            .into_iter()
            .map(|usage| (usage.vm_id.clone(), usage))
            .collect();
        let mut items = Vec::new();
        for rec in self.records()?.into_iter().filter(|r| !r.builder) {
            let running = rec.desired == Desired::Running && self.is_active(&rec.id).await;
            let pid = std::fs::read_to_string(self.run_spec(&rec).init_pid_file())
                .ok()
                .and_then(|raw| raw.trim().parse::<i32>().ok())
                .filter(|pid| *pid > 0);
            let connections = if running {
                pid.and_then(monitor::watcher_tcp_counts)
            } else {
                None
            };
            let summary = self.summary(&rec, running, &schedule.period(rec.created, now));
            let disk_image = std::fs::metadata(self.dir(&rec.id).join("disk.img"))
                .ok()
                .map(|metadata| {
                    use std::os::unix::fs::MetadataExt;
                    serde_json::json!({
                        "source": "runman_disk_image",
                        "available": true,
                        "sampled_at": now,
                        "logical_bytes": metadata.len(),
                        "allocated_bytes": metadata.blocks().saturating_mul(512)
                    })
                })
                .unwrap_or_else(|| {
                    serde_json::json!({
                        "source": "runman_disk_image",
                        "available": false,
                        "sampled_at": now
                    })
                });
            let spec = self.run_spec(&rec);
            let upper_mount = spec.mnt_upper();
            let upper_path = upper_mount.join("up");
            let upper_metrics = if running && sys::is_mountpoint(&upper_mount) {
                let path = upper_path.clone();
                tokio::task::spawn_blocking(move || monitor::upperdir_metrics(&path, 50_000))
                    .await
                    .ok()
                    .flatten()
                    .filter(|_| {
                        self.load(&rec.id).ok().flatten().is_some_and(|current| {
                            current.generation == rec.generation
                                && current.desired == Desired::Running
                        }) && sys::is_mountpoint(&upper_mount)
                    })
            } else {
                None
            };
            let writable_layer = upper_metrics.map_or_else(
                || {
                    serde_json::json!({
                        "source": "runman_overlay_upperdir_allocated",
                        "available": false,
                        "sampled_at": now
                    })
                },
                |metrics| {
                    serde_json::json!({
                        "source": "runman_overlay_upperdir_allocated",
                        "available": true,
                        "sampled_at": now,
                        "allocated_bytes": metrics.allocated_bytes,
                        "logical_file_bytes": metrics.logical_file_bytes,
                        "regular_files": metrics.regular_files
                    })
                },
            );
            let mut ips = vec![rec.addrs.ipv4.to_string()];
            if let Some(ip) = rec.addrs.ipv6 {
                ips.push(ip.to_string());
            }
            ips.extend(self.dedicated_for(&rec.id).iter().map(ToString::to_string));
            ips.sort();
            ips.dedup();
            let (established, pending, time_wait, udp_sockets, valid) = connections
                .map(|(established, pending, time_wait, udp_sockets)| {
                    (established, pending, time_wait, udp_sockets, true)
                })
                .unwrap_or((0, 0, 0, 0, false));
            let tcp_total = established + pending + time_wait;
            let usage = usage_by_vm.get(&rec.id);
            let usage_valid = usage.is_some_and(|u| {
                u.samples > 0
                    && u.avg.ts > 0
                    && now >= u.avg.ts
                    && now.saturating_sub(u.avg.ts) <= 180
            });
            let recent_metrics = usage.filter(|_| usage_valid);
            items.push(serde_json::json!({
                "id": &rec.id,
                "name": &rec.id,
                "instance_id": &rec.generation,
                "managed": true,
                "running": running,
                "status": if running { "running" } else { "stopped" },
                "network_quarantined": rec.network_quarantined,
                "os_image": &rec.os_image,
                "cpu": rec.cpu,
                "cpu_percent": summary.cpu_pct,
                "ram_mb": rec.ram_mb,
                "mem_bytes": summary.ram_used_mb.max(0) as u64 * 1_048_576,
                "mem_limit_bytes": rec.ram_mb.saturating_mul(1_048_576),
                "disk_gb": rec.disk_gb,
                "disk_image": disk_image,
                "writable_layer": writable_layer,
                "bandwidth_mbps": rec.bandwidth_mbps,
                "traffic_in_bytes": summary.traffic_in_bytes.max(0) as u64,
                "traffic_out_bytes": summary.traffic_out_bytes.max(0) as u64,
                "ips": ips,
                "init_pid": pid,
                "net_metrics_available": usage_valid,
                "monitor_metrics": {
                    "schema": 1,
                    "source": "runman_history",
                    "sampled_at": usage.map(|u| u.avg.ts).unwrap_or(0),
                    "window_seconds": 180,
                    "samples": usage.map(|u| u.samples).unwrap_or(0),
                    "valid": usage_valid,
                    "cpu_percent": recent_metrics.map(|u| u.avg.cpu),
                    "disk_used_bytes": recent_metrics.map(|u| u.avg.disk),
                    "disk_read_bytes_per_second": recent_metrics.map(|u| u.avg.rd),
                    "disk_write_bytes_per_second": recent_metrics.map(|u| u.avg.wr),
                    "disk_read_iops": recent_metrics.map(|u| u.avg.rio),
                    "disk_write_iops": recent_metrics.map(|u| u.avg.wio),
                    "net_rx_bits_per_second": recent_metrics.map(|u| u.avg.rx),
                    "net_tx_bits_per_second": recent_metrics.map(|u| u.avg.tx),
                    "net_rx_packets_per_second": recent_metrics.map(|u| u.avg.rxp),
                    "net_tx_packets_per_second": recent_metrics.map(|u| u.avg.txp),
                    "tcp_connections": recent_metrics.and_then(|u| u.avg.tcp),
                    "udp_flows": recent_metrics.and_then(|u| u.avg.udp),
                    "remote_ip_count": recent_metrics.and_then(|u| u.avg.ips)
                },
                "connection_metrics": {
                    "schema": 1,
                    "source": "runman_proc_net",
                    "sampled_at": now,
                    "epoch": rec.generation,
                    "valid": valid,
                    "total": tcp_total,
                    "tcp_total": tcp_total,
                    "tcp_established": established,
                    "tcp_pending": pending,
                    "tcp_time_wait": time_wait,
                    "udp_sockets": if valid { udp_sockets } else { 0 }
                }
            }));
        }
        Ok(serde_json::json!({
            "schema": 1,
            "observed_at": now,
            "bridge": &self.net.bridge,
            "items": items
        }))
    }

    /// Import only the explicitly supported, lossy Go migration contract.
    /// Guest files and addresses are not imported; the caller must keep the Go
    /// installation and its guest data intact until every check succeeds.
    pub async fn import_go_manifest(&self, path: &Path, max_forwards: u32) -> Result<usize> {
        let raw = std::fs::read(path)
            .with_context(|| format!("read migration manifest {}", path.display()))?;
        anyhow::ensure!(
            raw.len() <= 16 * 1024 * 1024,
            "migration manifest is too large"
        );
        let manifest: GoMigrationManifest =
            serde_json::from_slice(&raw).context("parse Go migration manifest")?;
        anyhow::ensure!(
            manifest.schema == 1,
            "unsupported Go migration manifest schema"
        );
        anyhow::ensure!(
            matches!(manifest.source_backend.as_str(), "podman" | "incus"),
            "unsupported source backend"
        );
        anyhow::ensure!(
            manifest.instances.len() <= 4096,
            "migration instance count exceeds 4096"
        );
        anyhow::ensure!(
            manifest.port_forwards.len() <= 65535,
            "too many port forwards in migration manifest"
        );

        let mut ids = HashSet::new();
        let mut instance_specs = Vec::with_capacity(manifest.instances.len());
        for item in &manifest.instances {
            let id = VmId::parse(&item.vm_id)?;
            anyhow::ensure!(ids.insert(id.to_string()), "duplicate VM ID {}", item.vm_id);
            anyhow::ensure!(
                matches!(item.os_image.as_str(), "alpine" | "debian"),
                "unsupported migration image {:?}",
                item.os_image
            );
            anyhow::ensure!(
                (1..=256).contains(&item.cpu),
                "CPU count is out of range for {}",
                item.vm_id
            );
            anyhow::ensure!(
                (128..=1_048_576).contains(&item.ram_mb),
                "memory is out of range for {}",
                item.vm_id
            );
            anyhow::ensure!(
                (1..=65_536).contains(&item.disk_gb),
                "disk size is out of range for {}",
                item.vm_id
            );
            anyhow::ensure!(
                item.bandwidth_mbps <= 10_000_000,
                "bandwidth is out of range for {}",
                item.vm_id
            );
            crate::model::validate_password(&item.root_password)?;
            instance_specs.push((
                id,
                crate::model::InstanceSpec {
                    vm_id: VmId::parse(&item.vm_id)?,
                    cpu: item.cpu,
                    ram_mb: item.ram_mb,
                    disk_gb: item.disk_gb,
                    bandwidth_mbps: item.bandwidth_mbps,
                    os_image: item.os_image.clone(),
                    root_password: item.root_password.clone(),
                },
                item.was_running,
            ));
        }

        let mut host_ports = HashSet::new();
        let mut forward_counts: HashMap<&str, u32> = HashMap::new();
        let mut forwards = Vec::with_capacity(manifest.port_forwards.len());
        for item in &manifest.port_forwards {
            anyhow::ensure!(
                ids.contains(&item.vm_id),
                "port forward references unknown VM {}",
                item.vm_id
            );
            anyhow::ensure!(
                item.host_port != 0 && item.guest_port != 0,
                "port forward has a zero port"
            );
            let proto = match item.protocol.as_str() {
                "tcp" => crate::model::L4Proto::Tcp,
                "udp" => crate::model::L4Proto::Udp,
                _ => anyhow::bail!("unsupported port-forward protocol {:?}", item.protocol),
            };
            anyhow::ensure!(
                host_ports.insert((proto, item.host_port)),
                "duplicate host port {}/{}",
                item.host_port,
                item.protocol
            );
            let count = forward_counts.entry(item.vm_id.as_str()).or_default();
            *count += 1;
            if max_forwards > 0 {
                anyhow::ensure!(
                    *count <= max_forwards,
                    "VM {} exceeds the preserved port-forward limit {}",
                    item.vm_id,
                    max_forwards
                );
            }
            forwards.push(crate::model::PortForward {
                vm_id: VmId::parse(&item.vm_id)?,
                proto,
                host_port: item.host_port,
                guest_port: item.guest_port,
                description: item.description.chars().take(200).collect(),
            });
        }

        for (id, spec, was_running) in instance_specs {
            crate::backend::Instances::create(self, &spec)
                .await
                .with_context(|| format!("rebuild Go VM {id}"))?;
            if !was_running {
                crate::backend::Instances::stop(self, &id, true)
                    .await
                    .with_context(|| format!("restore stopped state for {id}"))?;
            }
        }
        for forward in forwards {
            crate::backend::PortForwards::add(self, forward)
                .await
                .context("restore port forward")?;
        }
        Ok(ids.len())
    }

    fn allocate_idx(&self) -> Result<u32> {
        let used: BTreeSet<u32> = self.records()?.iter().map(|r| r.idx).collect();
        (0..=MAX_IDX.min(self.net.max_idx()))
            .find(|i| !used.contains(i))
            .context("no free instance slot")
    }

    /// Rebuild nftables/NDP state from the records and port forwards.
    async fn reconcile_network(&self) -> Result<()> {
        let forwards = self.forwards.lock().await;
        self.apply_network(&forwards).await
    }

    async fn apply_network(&self, forwards: &[PortForward]) -> Result<()> {
        let records = self.records()?;
        let by_id: HashMap<&str, &Record> = records.iter().map(|r| (r.id.as_str(), r)).collect();
        let dedicated = self.dedicated.lock().unwrap().clone();
        let instances: Vec<Port> = records
            .iter()
            .map(|r| Port {
                idx: r.idx,
                addrs: r.addrs.clone(),
                extra: dedicated.get(&r.id).cloned().unwrap_or_default(),
            })
            .collect();
        let resolved: Vec<Forward> = forwards
            .iter()
            .filter_map(|f| {
                by_id.get(f.vm_id.as_str()).map(|r| Forward {
                    proto: f.proto,
                    host_port: f.host_port,
                    target: r.addrs.ipv4,
                    guest_port: f.guest_port,
                })
            })
            .collect();
        self.net.apply(&instances, &resolved).await
    }

    fn save_forwards(&self, forwards: &[PortForward]) -> Result<()> {
        let stored: Vec<StoredForward> = forwards
            .iter()
            .map(|f| StoredForward {
                vm_id: f.vm_id.to_string(),
                proto: f.proto.as_str().into(),
                host_port: f.host_port,
                guest_port: f.guest_port,
                description: f.description.clone(),
            })
            .collect();
        fsutil::write_atomic(
            &self.data.join("portforwards.json"),
            &serde_json::to_vec_pretty(&stored)?,
        )
    }

    async fn is_active(&self, id: &str) -> bool {
        Command::new("systemctl")
            .args(["is-active", "--quiet", &unit_name(id)])
            .status()
            .await
            .is_ok_and(|s| s.success())
    }

    /// Build the disk image and prepare the rootfs for first boot.
    async fn provision(&self, rec: &Record, password: &str) -> Result<()> {
        let rs = self.run_spec(rec);
        for d in [
            rs.dir.clone(),
            rs.dir.join("mnt"),
            rs.mnt_disk(),
            rs.mnt_lower(),
            rs.mnt_upper(),
            rs.mnt_rootfs(),
        ] {
            mkdir_private(&d)?;
        }
        let disk = rs.disk_image();
        let _ = std::fs::remove_file(&disk);
        std::fs::File::create(&disk)?.set_len(rec.disk_gb << 30)?;
        run(Command::new("mkfs.ext4")
            .args([
                "-q",
                "-F",
                "-m",
                "0",
                "-E",
                "lazy_itable_init=1,lazy_journal_init=1",
            ])
            .arg(&disk))
        .await
        .context("mkfs.ext4")?;

        let hostname = rec.hostname.clone();
        let password = password.to_owned();
        let net = self.net_files(rec);
        self.with_offline_rootfs(rec, true, move |root| {
            customize::prepare(
                root,
                &customize::FirstBoot {
                    hostname: &hostname,
                    root_password: &password,
                    net: Some(net),
                },
            )
        })
        .await
    }

    /// Mount the (stopped) instance's overlay on the host and run `f` on it.
    async fn with_offline_rootfs<T: Send + 'static>(
        &self,
        rec: &Record,
        fresh: bool,
        f: impl FnOnce(&RootFs) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.with_offline_path(rec, fresh, move |path| f(&RootFs::open(path)?))
            .await
    }

    /// Like `with_offline_rootfs`, handing `f` the mounted path (for bulk
    /// copies; prefer `RootFs` for edits).
    async fn with_offline_path<T: Send + 'static>(
        &self,
        rec: &Record,
        fresh: bool,
        f: impl FnOnce(&Path) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let rs = self.run_spec(rec);
        let (disk, rootfs) = (rs.mnt_disk(), rs.mnt_rootfs());
        run(Command::new("mount")
            .args(["-t", "ext4", "-o", "loop,noatime,nodev"])
            .arg(rs.disk_image())
            .arg(&disk))
        .await
        .context("mount disk")?;
        let result = async {
            if fresh {
                for sub in ["up", "wk"] {
                    std::fs::create_dir_all(disk.join(sub))?;
                }
            }
            // Same `userxattr` as the in-container mount, so both read the
            // overlay metadata (whiteouts, opaque dirs) the same way.
            let opts = format!(
                "lowerdir={},upperdir={},workdir={},userxattr",
                rec.lower.display(),
                disk.join("up").display(),
                disk.join("wk").display()
            );
            run(Command::new("mount")
                .args(["-t", "overlay", "overlay", "-o", &opts])
                .arg(&rootfs))
            .await
            .context("mount overlay")?;
            let path = rootfs.clone();
            tokio::task::spawn_blocking(move || f(&path)).await?
        }
        .await;
        let _ = sys::umount_if_mounted(&rootfs);
        let _ = sys::umount_if_mounted(&disk);
        result
    }

    async fn launch(&self, rec: &Record) -> Result<()> {
        let unit = unit_name(&rec.id);
        let rs = self.run_spec(rec);
        let _ = std::fs::remove_file(rs.init_pid_file());
        let _ = Command::new("systemctl")
            .args(["reset-failed", &unit])
            .stderr(std::process::Stdio::null())
            .status()
            .await;
        let spec_path = rs.dir.join("runtime.json");
        run(Command::new("systemd-run")
            .arg(format!("--unit={unit}"))
            .arg(format!("--description=runman instance {}", rec.id))
            .args(["--collect", "--service-type=exec", "--quiet"])
            .args([
                "-p",
                "Delegate=yes",
                "-p",
                "PrivateMounts=yes",
                "-p",
                "KillMode=mixed",
            ])
            .args(["-p", "TimeoutStopSec=60", "-p", "OOMPolicy=continue"])
            .args(["-p", &format!("MemoryMax={}M", rec.ram_mb)])
            .args(["-p", &format!("MemoryHigh={}M", memory_high_mb(rec.ram_mb))])
            .args(["-p", &format!("MemorySwapMax={}M", rec.ram_mb)])
            .args(["-p", &format!("CPUQuota={}%", rec.cpu * 100)])
            .args(["-p", &format!("TasksMax={}", 1024 * rec.cpu.max(4))])
            .arg(&self.exe)
            .arg("__supervise")
            .arg(&spec_path))
        .await
        .context("systemd-run")?;

        let deadline = Instant::now() + START_TIMEOUT;
        while Instant::now() < deadline {
            if rs.init_pid_file().exists() {
                return Ok(());
            }
            if !self.is_active(&rec.id).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let log = Command::new("journalctl")
            .args(["-u", &unit, "-n", "5", "--no-pager", "-o", "cat"])
            .output()
            .await
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .replace('\n', "; ")
            })
            .unwrap_or_default();
        bail!("instance did not start: {log}")
    }

    async fn halt(&self, id: &str, force: bool) -> Result<()> {
        if !self.is_active(id).await {
            return Ok(());
        }
        let unit = unit_name(id);
        if force {
            // Kill only the instance; the supervisor sees init die and cleans
            // up (killing it too would leak its network devices and mounts).
            let _ = std::fs::write(unit_cgroup(id).join("ct/cgroup.kill"), "1");
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.is_active(id).await && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        // The unit may finish and be garbage-collected (`--collect`) while we
        // ask, which systemctl reports as "not loaded": that is success too.
        match run(Command::new("systemctl").args(["stop", &unit])).await {
            Err(e) if self.is_active(id).await => Err(e),
            _ => Ok(()),
        }
    }

    fn set_desired(&self, id: &VmId, desired: Desired) -> Result<Record> {
        let mut rec = self.require(id)?;
        if rec.desired != desired {
            rec.desired = desired;
            self.save(&rec)?;
        }
        Ok(rec)
    }

    /// Repair host state that something else removed: re-apply the nftables
    /// ruleset (atomic, so harmless when nothing changed) and re-plug running
    /// instances whose veth vanished (`ip link del`, network restarts).
    pub async fn heal(&self) {
        if let Err(e) = self.reconcile_network().await {
            warn!("re-apply network rules: {e:#}");
        }
        let Ok(records) = self.records() else { return };
        for rec in &records {
            let rs = self.run_spec(rec);
            if let Some(pid) = std::fs::read_to_string(rs.init_pid_file())
                .ok()
                .and_then(|p| p.trim().parse::<i32>().ok())
            {
                let moved = exec::adopt_strays(&unit_cgroup(&rec.id), pid);
                if moved > 0 {
                    info!(
                        "instance {}: moved {moved} process(es) into its cgroup",
                        rec.id
                    );
                }
            }
        }
        for snapshot in records {
            let _g = self.lock_vm(&snapshot.id).await;
            let Ok(Some(rec)) = self.load(&snapshot.id) else {
                continue;
            };
            let host_if = self.net.host_if(rec.idx);
            let master =
                std::fs::read_link(Path::new("/sys/class/net").join(&host_if).join("master"));
            let attached = master
                .ok()
                .and_then(|m| m.file_name().map(|n| n == self.net.bridge.as_str()))
                == Some(true);
            if !self.is_active(&rec.id).await {
                continue;
            }
            if attached {
                match attach::host_link_up(&host_if) {
                    Ok(up) if up == !rec.network_quarantined => continue,
                    Ok(_) => {
                        warn!(
                            "instance {}: restoring {} host link state to match quarantine record",
                            rec.id, host_if
                        );
                        let interface = host_if.clone();
                        let wanted_up = !rec.network_quarantined;
                        match tokio::task::spawn_blocking(move || {
                            attach::set_host_link_up(&interface, wanted_up)
                        })
                        .await
                        {
                            Ok(Ok(())) => continue,
                            Ok(Err(e)) => {
                                warn!("instance {}: restore network link state: {e:#}", rec.id)
                            }
                            Err(e) => warn!("instance {}: restore network link state: {e}", rec.id),
                        }
                        continue;
                    }
                    Err(e) => {
                        warn!("instance {}: read network link state: {e:#}", rec.id);
                        continue;
                    }
                }
            }
            // No init.pid while the supervisor is (re)booting the instance;
            // it attaches the network itself then.
            let rs = self.run_spec(&rec);
            let Some(pid) = std::fs::read_to_string(rs.init_pid_file())
                .ok()
                .and_then(|p| p.trim().parse::<i32>().ok())
            else {
                continue;
            };
            let Some(spec) = rs.net.clone() else { continue };
            warn!(
                "instance {}: {host_if} is missing from {}, re-attaching",
                rec.id, self.net.bridge
            );
            match tokio::task::spawn_blocking(move || attach::attach(&spec, pid)).await {
                Ok(Ok(())) => {
                    if let Err(e) = self.update_instance_network(&rec).await {
                        warn!("instance {}: reconfigure eth0: {e:#}", rec.id);
                    }
                }
                Ok(Err(e)) => warn!("instance {}: re-attach network: {e:#}", rec.id),
                Err(e) => warn!("instance {}: re-attach network: {e}", rec.id),
            }
        }
    }

    /// The schedule in effect, switching to the configured one if it
    /// changed. A change keeps the usage counted so far: counters of the
    /// current period are relabelled to the new schedule's period, so they
    /// restart at its next reset, not right away.
    fn traffic_schedule(&self) -> std::sync::MutexGuard<'_, Schedule> {
        let mut seen = self.schedule.lock().unwrap();
        let Some(wanted) = self.config.as_ref().map(|c| c.get().traffic_schedule()) else {
            return seen;
        };
        if wanted != *seen {
            let now = unix_now();
            info!(
                "traffic schedule: {:?}, day {}, UTC{:+}min",
                wanted.mode, wanted.reset_day, wanted.utc_offset_min
            );
            for rec in self.records().unwrap_or_default() {
                let old = seen.period(rec.created, now);
                let new = wanted.period(rec.created, now);
                let mut t = self.load_traffic(&rec.id);
                if old != new && t.period == old {
                    t.period = new;
                    self.save_traffic(&rec.id, &t);
                }
            }
            *seen = wanted;
        }
        seen
    }

    fn save_traffic(&self, id: &str, t: &Traffic) {
        let result = serde_json::to_vec(t)
            .map_err(anyhow::Error::from)
            .and_then(|raw| fsutil::write_atomic(&self.dir(id).join("traffic.json"), &raw));
        if let Err(e) = result {
            warn!("traffic {id}: {e:#}");
        }
    }

    fn load_traffic(&self, id: &str) -> Traffic {
        std::fs::read(self.dir(id).join("traffic.json"))
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default()
    }

    /// Fold the current veth counters of running instances into their
    /// persisted totals. Call periodically (and before deleting nothing:
    /// totals of deleted instances are discarded with them).
    pub async fn sample_traffic(&self) {
        let schedule = self.traffic_schedule();
        let now = unix_now();
        let Ok(records) = self.records() else { return };
        for rec in records {
            let period = schedule.period(rec.created, now);
            let base = Path::new("/sys/class/net").join(self.net.host_if(rec.idx));
            let read = |name: &str| -> Option<u64> {
                std::fs::read_to_string(base.join(name))
                    .ok()?
                    .trim()
                    .parse()
                    .ok()
            };
            let (Some(ifindex), Some(rx), Some(tx)) = (
                read("ifindex"),
                read("statistics/rx_bytes"),
                read("statistics/tx_bytes"),
            ) else {
                continue; // not running
            };
            let mut t = self.load_traffic(&rec.id);
            t.update(ifindex as u32, rx, tx, &period);
            self.save_traffic(&rec.id, &t);
        }
        drop(schedule);
    }

    fn summary(&self, rec: &Record, active: bool, period: &str) -> proto::VmSummary {
        let traffic = self.load_traffic(&rec.id);
        let (month_in, month_out) = traffic.month(period);
        let mut ips = vec![rec.addrs.ipv4.to_string()];
        ips.extend(rec.addrs.ipv6.map(|a| a.to_string()));
        let mut s = proto::VmSummary {
            vm_id: rec.id.clone(),
            status: if active {
                proto::VmStatus::Running
            } else {
                proto::VmStatus::Stopped
            } as i32,
            ips,
            traffic_in_bytes: traffic.total_in as i64,
            traffic_out_bytes: traffic.total_out as i64,
            monthly_traffic_in: month_in as i64,
            monthly_traffic_out: month_out as i64,
            ..Default::default()
        };
        if active {
            let cg = unit_cgroup(&rec.id);
            s.ram_used_mb = memory_used(&cg).map_or(0, |b| (b >> 20) as i64);
            if let Some(usage) = cpu_usage_usec(&cg) {
                let mut samples = self.cpu_samples.lock().unwrap();
                let now = Instant::now();
                if let Some((at, prev)) = samples.insert(rec.id.clone(), (now, usage)) {
                    let elapsed = now.duration_since(at).as_micros() as f64;
                    if elapsed > 0.0 {
                        let pct =
                            (usage.saturating_sub(prev)) as f64 / elapsed / f64::from(rec.cpu)
                                * 100.0;
                        s.cpu_pct = pct.clamp(0.0, 100.0) as f32;
                    }
                }
            }
        }
        s
    }
}

fn load_forwards(path: &Path) -> Result<Vec<PortForward>> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let stored: Vec<StoredForward> =
        serde_json::from_slice(&raw).context("parse portforwards.json")?;
    stored
        .into_iter()
        .map(|s| {
            Ok(PortForward {
                vm_id: VmId::parse(&s.vm_id)?,
                proto: if s.proto == "udp" {
                    L4Proto::Udp
                } else {
                    L4Proto::Tcp
                },
                host_port: s.host_port,
                guest_port: s.guest_port,
                description: s.description,
            })
        })
        .collect()
}

/// Status check for reports (no process spawn per instance): the unit's
/// cgroup exists and holds processes. Lifecycle operations still ask systemd.
fn unit_running(id: &str) -> bool {
    std::fs::read_to_string(unit_cgroup(id).join("cgroup.events"))
        .is_ok_and(|e| e.contains("populated 1"))
}

fn read_kv(path: &Path, key: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.lines().find_map(|l| {
        let (k, v) = l.split_once(' ')?;
        (k == key).then(|| v.trim().parse().ok()).flatten()
    })
}

fn cpu_usage_usec(cg: &Path) -> Option<u64> {
    read_kv(&cg.join("cpu.stat"), "usage_usec")
}

/// Like `free`: total charge minus reclaimable page cache.
fn memory_used(cg: &Path) -> Option<u64> {
    let current: u64 = std::fs::read_to_string(cg.join("memory.current"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let inactive = read_kv(&cg.join("memory.stat"), "inactive_file").unwrap_or(0);
    Some(current.saturating_sub(inactive))
}

/// Above this the kernel throttles and reclaims instead of OOM-killing at
/// `MemoryMax`. Without the margin, a large write fills the instance's memory
/// with dirty pages faster than the disk takes them, and the OOM killer picks
/// the instance's init.
fn memory_high_mb(ram_mb: u64) -> u64 {
    ram_mb - (ram_mb / 8).clamp(16, 256).min(ram_mb / 2)
}

fn hostname_for(id: &str) -> String {
    format!("vps-{}", &id[..8])
}

impl Runtime {
    /// `create` with the instance lock held.
    async fn create_locked(&self, spec: &InstanceSpec, builder: bool) -> Result<()> {
        let id = spec.vm_id.as_str();
        // Checked before an existing instance is replaced. Builds may start
        // from any image.
        if !builder && !self.images.is_enabled(&spec.os_image) {
            bail!("image {:?} is disabled on this node", spec.os_image);
        }
        // Replacing an instance (reinstall, or a repeated create) keeps its
        // creation time and traffic counters: a reinstall must not hand out
        // a fresh monthly quota.
        let mut carried = None;
        if let Some(old) = self.load(id)? {
            carried = Some((old.created, self.load_traffic(id)));
        }
        if carried.is_some() || self.dir(id).exists() {
            info!("create {id}: replacing existing instance");
            self.delete_locked(&spec.vm_id).await?;
        }
        let (created, traffic) = match carried {
            Some((c, t)) if c > 0 => (c, Some(t)),
            Some((_, t)) => (unix_now(), Some(t)),
            None => (unix_now(), None),
        };
        // Choosing an index and writing the record that claims it must be one
        // step: creates of different instances run concurrently, and two of
        // them picking the same free index would share a veth name and
        // addresses. The slow part (disk, boot) runs outside the lock.
        let alloc = self.alloc.lock().unwrap();
        // Under the same lock as image GC: the serial chosen here is claimed
        // by the record below before GC can consider it unused.
        let image = self.images.get(&spec.os_image)?;
        let idx = self.allocate_idx()?;
        let rec = Record {
            id: id.to_owned(),
            generation: uuid::Uuid::new_v4().to_string(),
            idx,
            cpu: spec.cpu,
            ram_mb: spec.ram_mb,
            disk_gb: spec.disk_gb,
            bandwidth_mbps: spec.bandwidth_mbps,
            os_image: spec.os_image.clone(),
            lower: image.rootfs.clone(),
            stop_signal: image.stop_signal.clone(),
            hostname: hostname_for(id),
            addrs: self.net.addrs_for(idx)?,
            desired: Desired::Running,
            network_quarantined: false,
            network_pending: false,
            builder,
            created,
        };
        mkdir_private(&self.dir(id))?;
        self.save(&rec)?;
        if let Some(t) = &traffic {
            self.save_traffic(id, t);
        }
        drop(alloc);
        let started = Instant::now();
        if let Err(e) = self.provision(&rec, &spec.root_password).await {
            let _ = std::fs::remove_dir_all(self.dir(id));
            return Err(e.context("provision instance"));
        }
        self.reconcile_network().await?;
        self.launch(&rec).await?;
        info!(
            "instance {id} created from {} in {:?}",
            image.name,
            started.elapsed()
        );
        Ok(())
    }

    /// `delete` with the instance lock held.
    async fn delete_locked(&self, id: &VmId) -> Result<()> {
        self.halt(id.as_str(), true).await?;
        let dir = self.dir(id.as_str());
        if let Some(rec) = self.load(id.as_str())? {
            // Safety net if the supervisor died without cleaning up.
            let ifb = format!("{}i", self.net.host_if(rec.idx));
            if Path::new("/sys/class/net").join(&ifb).exists() {
                let _ = run(Command::new("ip").args(["link", "del", &ifb])).await;
            }
        }
        if dir.exists() {
            for sub in ["mnt/rootfs", "mnt/disk"] {
                sys::umount_if_mounted(&dir.join(sub))?;
            }
            tokio::fs::remove_dir_all(&dir)
                .await
                .with_context(|| format!("remove {}", dir.display()))?;
        }
        let _ = std::fs::remove_dir_all(Path::new(RUN_ROOT).join(id.as_str()));
        self.cpu_samples.lock().unwrap().remove(id.as_str());
        self.reconcile_network().await
    }
}

#[async_trait]
impl Instances for Runtime {
    async fn create(&self, spec: &InstanceSpec) -> Result<()> {
        let _g = self.lock_vm(spec.vm_id.as_str()).await;
        self.create_locked(spec, false).await
    }

    async fn reinstall(&self, spec: &InstanceSpec) -> Result<()> {
        // Delete + create gives a clean disk; port forwards are keyed by the
        // instance id and follow it to its (possibly new) address.
        let _g = self.lock_vm(spec.vm_id.as_str()).await;
        self.create_locked(spec, false).await
    }

    async fn start(&self, id: &VmId) -> Result<()> {
        let _g = self.lock_vm(id.as_str()).await;
        let rec = self.set_desired(id, Desired::Running)?;
        if self.is_active(id.as_str()).await {
            return Ok(());
        }
        self.save(&rec)?; // refresh runtime.json for the current binary/layout
        self.launch(&rec).await
    }

    async fn stop(&self, id: &VmId, force: bool) -> Result<()> {
        let _g = self.lock_vm(id.as_str()).await;
        self.set_desired(id, Desired::Stopped)?;
        self.halt(id.as_str(), force).await
    }

    async fn restart(&self, id: &VmId) -> Result<()> {
        let _g = self.lock_vm(id.as_str()).await;
        let rec = self.set_desired(id, Desired::Running)?;
        self.halt(id.as_str(), false).await?;
        self.launch(&rec).await
    }

    async fn delete(&self, id: &VmId) -> Result<()> {
        let _g = self.lock_vm(id.as_str()).await;
        self.delete_locked(id).await?;
        // A reinstall (delete_locked + create) keeps the history.
        if let Err(e) = self.history.forget(id.as_str()) {
            warn!("instance {id}: drop metrics: {e:#}");
        }
        Ok(())
    }

    async fn reset_password(&self, id: &VmId, password: &str) -> Result<()> {
        let _g = self.lock_vm(id.as_str()).await;
        let rec = self.require(id)?;
        let hash = customize::hash_password(password)?;
        if self.is_active(id.as_str()).await {
            let line = format!("root:{hash}\n");
            self.exec_target(id.as_str())
                .run(&["chpasswd", "-e"], line.as_bytes())
                .await
        } else {
            self.with_offline_rootfs(&rec, false, move |root| {
                customize::set_root_password(root, &hash)
            })
            .await
        }
    }

    async fn list(&self) -> Result<Vec<proto::VmSummary>> {
        let schedule = *self.traffic_schedule();
        let now = unix_now();
        let mut out = Vec::new();
        for rec in self.records()?.into_iter().filter(|r| !r.builder) {
            let active = unit_running(&rec.id);
            out.push(self.summary(&rec, active, &schedule.period(rec.created, now)));
        }
        Ok(out)
    }

    async fn images(&self) -> Result<Vec<proto::OsImageInfo>> {
        Ok(self
            .images
            .enabled()
            .into_iter()
            .map(|i| proto::OsImageInfo {
                id: i.id,
                name: i.name,
            })
            .collect())
    }

    async fn details(&self) -> Result<Vec<InstanceDetails>> {
        let schedule = *self.traffic_schedule();
        let now = unix_now();
        let mut out = Vec::new();
        for rec in self.records()?.into_iter().filter(|r| !r.builder) {
            let active = unit_running(&rec.id);
            let period = schedule.period(rec.created, now);
            let mut d = InstanceDetails::from_summary(&self.summary(&rec, active, &period));
            d.created = rec.created;
            d.traffic_next_reset = schedule.next_reset(rec.created, now);
            d.hostname = rec.hostname.clone();
            d.cpu = rec.cpu;
            d.ram_mb = rec.ram_mb;
            d.disk_gb = rec.disk_gb;
            d.bandwidth_mbps = rec.bandwidth_mbps;
            d.os_image = rec.os_image.clone();
            d.dedicated = self
                .dedicated_for(&rec.id)
                .iter()
                .map(ToString::to_string)
                .collect();
            out.push(d);
        }
        Ok(out)
    }

    async fn console_log(&self, id: &VmId, max_bytes: usize) -> Result<String> {
        use std::io::{Read, Seek, SeekFrom};
        self.require(id)?;
        let path = self.dir(id.as_str()).join("console.log");
        let Ok(mut f) = std::fs::File::open(&path) else {
            return Ok(String::new());
        };
        let len = f.metadata()?.len();
        f.seek(SeekFrom::Start(len.saturating_sub(max_bytes as u64)))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    async fn open_console(&self, id: &VmId, size: Option<ConsoleSize>) -> Result<ConsoleIo> {
        self.require(id)?;
        if !self.is_active(id.as_str()).await {
            bail!("instance {id} is not running");
        }
        self.exec_target(id.as_str()).console(size)
    }
}

#[async_trait]
impl PortForwards for Runtime {
    async fn add(&self, rule: PortForward) -> Result<()> {
        self.require(&rule.vm_id)?;
        let mut forwards = self.forwards.lock().await;
        if let Some(existing) = forwards
            .iter()
            .find(|f| f.proto == rule.proto && f.host_port == rule.host_port)
        {
            if existing.vm_id == rule.vm_id && existing.guest_port == rule.guest_port {
                return Ok(());
            }
            bail!(
                "host port {}/{} is already forwarded",
                rule.host_port,
                rule.proto.as_str()
            );
        }
        if net::host_listening(rule.proto, rule.host_port) {
            bail!(
                "host port {}/{} is used by a host service",
                rule.host_port,
                rule.proto.as_str()
            );
        }
        let mut next = forwards.clone();
        next.push(rule);
        self.apply_network(&next).await?;
        self.save_forwards(&next)?;
        *forwards = next;
        Ok(())
    }

    async fn remove(&self, id: &VmId, proto: L4Proto, host_port: u16) -> Result<()> {
        let mut forwards = self.forwards.lock().await;
        let mut next = forwards.clone();
        next.retain(|f| !(&f.vm_id == id && f.proto == proto && f.host_port == host_port));
        if next.len() == forwards.len() {
            return Ok(());
        }
        self.apply_network(&next).await?;
        self.save_forwards(&next)?;
        *forwards = next;
        Ok(())
    }

    async fn list(&self, id: Option<&VmId>) -> Result<Vec<PortForward>> {
        let forwards = self.forwards.lock().await;
        Ok(forwards
            .iter()
            .filter(|f| id.is_none_or(|id| &f.vm_id == id))
            .cloned()
            .collect())
    }

    async fn remove_all(&self, id: &VmId) -> Result<()> {
        let mut forwards = self.forwards.lock().await;
        let mut next = forwards.clone();
        next.retain(|f| &f.vm_id != id);
        if next.len() == forwards.len() {
            return Ok(());
        }
        self.apply_network(&next).await?;
        self.save_forwards(&next)?;
        *forwards = next;
        Ok(())
    }

    async fn free_port(&self) -> Result<u16> {
        let forwards = self.forwards.lock().await;
        let mut rng = rand::rng();
        for _ in 0..200 {
            let port = rng.random_range(AUTO_PORTS);
            let taken = forwards.iter().any(|f| f.host_port == port)
                || net::host_listening(L4Proto::Tcp, port)
                || net::host_listening(L4Proto::Udp, port);
            if !taken {
                return Ok(port);
            }
        }
        bail!("no free host port in {AUTO_PORTS:?}")
    }
}

#[async_trait]
impl WgBindings for Runtime {
    async fn reconcile(&self, desired: Vec<proto::WgBindDesired>) -> Result<()> {
        let bindings: Vec<wg::Binding> = desired
            .iter()
            .filter_map(|d| match wg::Binding::from_proto(d) {
                Ok(b) => Some(b),
                Err(e) => {
                    warn!("wg {}: ignoring invalid binding: {e:#}", d.resource_id);
                    None
                }
            })
            .collect();
        let mut tunnels = self.tunnels.lock().await;
        if bindings.iter().any(|b| b.address.is_ipv6()) {
            self.net.enable_v6().await?;
        }
        tunnels.reconcile(&bindings).await?;
        let after = tunnels.addresses_by_vm();
        let before = std::mem::replace(&mut *self.dedicated.lock().unwrap(), after.clone());

        let mut todo = std::mem::take(&mut *self.net_pending.lock().unwrap());
        for vm in before.keys().chain(after.keys()) {
            if before.get(vm) != after.get(vm) {
                todo.insert(vm.clone());
            }
        }
        if todo.is_empty() {
            return Ok(());
        }
        // Anti-spoofing sets must allow the new source addresses first.
        self.reconcile_network().await?;
        for vm in todo {
            let Ok(id) = VmId::parse(&vm) else { continue };
            let _g = self.lock_vm(id.as_str()).await;
            let Some(rec) = self.load(id.as_str())? else {
                continue; // bound to an instance that is not on this host
            };
            match self.update_instance_network(&rec).await {
                Ok(()) => info!(
                    "instance {vm}: dedicated addresses now {:?}",
                    self.dedicated_for(&vm)
                ),
                Err(e) => {
                    warn!("instance {vm}: apply dedicated addresses: {e:#}");
                    self.net_pending.lock().unwrap().insert(vm);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_high_leaves_a_margin() {
        assert_eq!(memory_high_mb(128), 112);
        assert_eq!(memory_high_mb(1024), 896);
        assert_eq!(memory_high_mb(8192), 7936);
        assert_eq!(memory_high_mb(16), 8);
    }
}

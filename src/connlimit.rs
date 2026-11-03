//! Temporary per-instance TCP connection caps for Runman-managed containers.
//!
//! Policies are tied to a VM UUID and an instance generation. They are
//! persisted before firewall changes and reconciled after restart, address
//! changes, stop/start, deletion, and lease expiry. The dedicated iptables
//! chain only matches the configured Runman bridge.

use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::warn;

const CHAIN: &str = "RUNMAN_RS_CLIMIT";
const CHAIN_MARKER: &str = "runman-agent-rs-v2";

#[derive(Debug, Clone)]
pub struct Target {
    pub managed: bool,
    pub running: bool,
    pub instance_id: String,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub id: String,
    pub vm_id: String,
    pub instance_id: String,
    pub max_connections: u32,
    pub expires_at: i64,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub remove_only: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    policies: Vec<Policy>,
}

pub struct Manager {
    path: PathBuf,
    bridge: String,
    state: tokio::sync::Mutex<State>,
    changed: tokio::sync::Notify,
}

impl Manager {
    pub fn new(path: PathBuf, bridge: String) -> Result<Self> {
        if bridge.is_empty()
            || bridge.len() > 15
            || !bridge
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            bail!("invalid Runman bridge interface");
        }
        let state = load_state(&path)?;
        Ok(Self {
            path,
            bridge,
            state: tokio::sync::Mutex::new(state),
            changed: tokio::sync::Notify::new(),
        })
    }

    pub async fn apply(&self, mut policy: Policy, target: &Target) -> Result<()> {
        validate_policy(&policy)?;
        if !target.managed || !target.running {
            bail!("target is not a running Runman-managed instance");
        }
        if target.instance_id != policy.instance_id {
            bail!("instance identity changed; no connection-limit rule was applied");
        }
        policy.ips = validate_ips(&target.ips)?;
        if policy.ips.is_empty() {
            bail!("managed instance has no usable addresses");
        }

        let mut state = self.state.lock().await;
        if let Some(index) = state.policies.iter().position(|old| old.id == policy.id) {
            let old = state.policies[index].clone();
            if old.vm_id != policy.vm_id
                || old.instance_id != policy.instance_id
                || old.max_connections != policy.max_connections
            {
                bail!("policy ID already exists with different contents");
            }
            if old.remove_only {
                bail!("connection-limit policy cleanup is pending");
            }
            if old.expires_at <= now() {
                bail!("connection-limit policy has expired; issue a new policy ID");
            }
            if old.ips != policy.ips {
                self.remove_rules(&old).await?;
                state.policies[index].ips = policy.ips.clone();
                self.save(&state)?;
                let refreshed = state.policies[index].clone();
                if let Err(e) = self.install_rules(&refreshed).await {
                    state.policies[index].remove_only = true;
                    self.save(&state)?;
                    self.changed.notify_one();
                    return Err(e.context("refresh per-instance TCP connection limit"));
                }
            } else {
                self.install_rules(&old).await?;
            }
            return Ok(());
        }
        if state.policies.iter().any(|old| {
            old.vm_id == policy.vm_id
                && old.instance_id == policy.instance_id
                && old.expires_at > now()
        }) {
            bail!("an unexpired connection limit already exists for this instance");
        }
        state.policies.push(policy.clone());
        self.save(&state)?;
        if let Err(cause) = self.install_rules(&policy).await {
            if let Some(stored) = state.policies.iter_mut().find(|p| p.id == policy.id) {
                stored.remove_only = true;
            }
            self.save(&state)?;
            self.changed.notify_one();
            return Err(cause.context("apply per-instance TCP connection limit"));
        }
        self.changed.notify_one();
        Ok(())
    }

    pub async fn release(&self, id: &str, vm_id: &str, instance_id: &str) -> Result<()> {
        if !valid_policy_id(id) || vm_id.is_empty() {
            bail!("invalid connection-limit release identity");
        }
        crate::model::VmId::parse(vm_id).context("invalid Runman VM UUID")?;
        if !instance_id.is_empty() {
            uuid::Uuid::parse_str(instance_id).context("invalid instance generation identity")?;
        }
        let mut state = self.state.lock().await;
        let Some(index) = state.policies.iter().position(|p| p.id == id) else {
            return Ok(());
        };
        let mut policy = state.policies[index].clone();
        if policy.vm_id != vm_id || (!instance_id.is_empty() && policy.instance_id != instance_id) {
            bail!("connection-limit policy target identity mismatch");
        }
        policy.remove_only = true;
        state.policies[index] = policy.clone();
        self.save(&state)?;
        self.changed.notify_one();
        self.remove_rules(&policy).await?;
        state.policies.retain(|p| p.id != id);
        self.save(&state)?;
        self.cleanup_chain_if_empty(&state).await?;
        self.changed.notify_one();
        Ok(())
    }

    async fn wait_for_reconcile(&self) {
        let notified = self.changed.notified();
        let delay = {
            let state = self.state.lock().await;
            state
                .policies
                .iter()
                .filter(|policy| !policy.remove_only)
                .map(|policy| policy.expires_at.saturating_sub(now()).max(1) as u64)
                .min()
                .map(|seconds| std::time::Duration::from_secs(seconds.min(30)))
                .unwrap_or_else(|| std::time::Duration::from_secs(30))
        };
        tokio::select! {
            _ = notified => {},
            _ = tokio::time::sleep(delay) => {},
        }
    }

    /// Revalidate saved policies against current instance records. `resolve`
    /// must return only records created by this Runtime, never an arbitrary
    /// host/container lookup.
    pub async fn reconcile<F, Fut>(&self, resolve: F) -> Result<()>
    where
        F: Fn(String) -> Fut,
        Fut: Future<Output = Result<Target>>,
    {
        let mut state = self.state.lock().await;
        let mut failures = Vec::new();
        let mut i = 0;
        while i < state.policies.len() {
            let policy = state.policies[i].clone();
            if policy.remove_only || policy.expires_at <= now() {
                if let Err(e) = self.remove_rules(&policy).await {
                    failures.push(e.context(format!("remove expired policy {}", policy.id)));
                    i += 1;
                    continue;
                }
                state.policies.remove(i);
                if let Err(e) = self.save(&state) {
                    failures.push(e.context("persist expired policy cleanup"));
                    i += 1;
                }
                continue;
            }

            let target = match resolve(policy.vm_id.clone()).await {
                Ok(target) => target,
                Err(e) => {
                    failures.push(e.context(format!("resolve managed instance {}", policy.vm_id)));
                    i += 1;
                    continue;
                }
            };
            if !target.managed || target.instance_id != policy.instance_id {
                if let Err(e) = self.remove_rules(&policy).await {
                    failures.push(e.context(format!("remove stale policy {}", policy.id)));
                    i += 1;
                    continue;
                }
                state.policies.remove(i);
                if let Err(e) = self.save(&state) {
                    failures.push(e.context("persist stale policy cleanup"));
                    i += 1;
                }
                continue;
            }

            let current_ips = validate_ips(&target.ips).unwrap_or_default();
            if !target.running || current_ips.is_empty() {
                if let Err(e) = self.remove_rules(&policy).await {
                    failures.push(e.context(format!("remove stopped target policy {}", policy.id)));
                    i += 1;
                    continue;
                }
                if !policy.ips.is_empty() {
                    state.policies[i].ips.clear();
                    if let Err(e) = self.save(&state) {
                        failures.push(e.context("persist suspended connection-limit policy"));
                    }
                }
                i += 1;
                continue;
            }

            if current_ips != policy.ips {
                if let Err(e) = self.remove_rules(&policy).await {
                    failures.push(e.context(format!("replace addresses for policy {}", policy.id)));
                    i += 1;
                    continue;
                }
                state.policies[i].ips = current_ips;
                if let Err(e) = self.save(&state) {
                    failures.push(e.context("persist connection-limit addresses"));
                    i += 1;
                    continue;
                }
            }
            let current = state.policies[i].clone();
            if let Err(e) = self.install_rules(&current).await {
                failures.push(e.context(format!("reinstall policy {}", current.id)));
            }
            i += 1;
        }
        self.cleanup_chain_if_empty(&state).await?;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "{} connection-limit reconciliation error(s): {}",
                failures.len(),
                failures
                    .into_iter()
                    .map(|e| format!("{e:#}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        }
    }

    async fn install_rules(&self, policy: &Policy) -> Result<()> {
        self.ensure_chain().await?;
        for raw in &policy.ips {
            let ip: IpAddr = raw.parse().context("invalid persisted instance address")?;
            let tool = if ip.is_ipv6() {
                "ip6tables"
            } else {
                "iptables"
            };
            for incoming in [false, true] {
                let args = self.rule_args(policy, ip, incoming);
                let mut check = vec!["-C".to_owned(), CHAIN.to_owned()];
                check.extend(args.clone());
                if command(tool, &check).await.is_ok() {
                    continue;
                }
                let mut add = vec!["-I".to_owned(), CHAIN.to_owned(), "1".to_owned()];
                add.extend(args);
                command(tool, &add).await?;
            }
        }
        Ok(())
    }

    async fn remove_rules(&self, policy: &Policy) -> Result<()> {
        for raw in &policy.ips {
            let Ok(ip) = raw.parse::<IpAddr>() else {
                continue;
            };
            let tool = if ip.is_ipv6() {
                "ip6tables"
            } else {
                "iptables"
            };
            for incoming in [false, true] {
                let args = self.rule_args(policy, ip, incoming);
                loop {
                    let mut check = vec!["-C".to_owned(), CHAIN.to_owned()];
                    check.extend(args.clone());
                    if command(tool, &check).await.is_err() {
                        break;
                    }
                    let mut delete = vec!["-D".to_owned(), CHAIN.to_owned()];
                    delete.extend(args.clone());
                    command(tool, &delete).await?;
                }
            }
        }
        Ok(())
    }

    fn rule_args(&self, policy: &Policy, ip: IpAddr, incoming: bool) -> Vec<String> {
        let (direction, iface, address, conn_direction, label) = if incoming {
            ("-o", self.bridge.as_str(), "-d", "--connlimit-daddr", "in")
        } else {
            ("-i", self.bridge.as_str(), "-s", "--connlimit-saddr", "out")
        };
        let mask = if ip.is_ipv6() { "128" } else { "32" };
        vec![
            direction.into(),
            iface.into(),
            address.into(),
            ip.to_string(),
            "-p".into(),
            "tcp".into(),
            "--syn".into(),
            "-m".into(),
            "connlimit".into(),
            "--connlimit-above".into(),
            policy.max_connections.to_string(),
            "--connlimit-mask".into(),
            mask.into(),
            conn_direction.into(),
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            format!("runman-rs-climit:{}:{label}", policy.id),
            "-j".into(),
            "REJECT".into(),
            "--reject-with".into(),
            "tcp-reset".into(),
        ]
    }

    async fn ensure_chain(&self) -> Result<()> {
        let state = command_output("iptables", &["-S", CHAIN]).await;
        if state.is_err() {
            command("iptables", &["-N", CHAIN])
                .await
                .or_else(|create_error| {
                    Err(create_error.context("create managed IPv4 connection-limit chain"))
                })?;
            command(
                "iptables",
                &[
                    "-A",
                    CHAIN,
                    "-m",
                    "comment",
                    "--comment",
                    CHAIN_MARKER,
                    "-j",
                    "RETURN",
                ],
            )
            .await?;
        } else if !state.unwrap_or_default().contains(CHAIN_MARKER) {
            bail!("refusing to modify an existing unowned IPv4 chain {CHAIN}");
        }
        for tool in ["iptables", "ip6tables"] {
            if tool == "ip6tables" {
                let state = command_output(tool, &["-S", CHAIN]).await;
                if state.is_err() {
                    command(tool, &["-N", CHAIN]).await?;
                    command(
                        tool,
                        &[
                            "-A",
                            CHAIN,
                            "-m",
                            "comment",
                            "--comment",
                            CHAIN_MARKER,
                            "-j",
                            "RETURN",
                        ],
                    )
                    .await?;
                } else if !state.unwrap_or_default().contains(CHAIN_MARKER) {
                    bail!("refusing to modify an existing unowned IPv6 chain {CHAIN}");
                }
            }
            let jump = command(tool, &["-C", "FORWARD", "-j", CHAIN]).await;
            if jump.is_err() {
                command(tool, &["-I", "FORWARD", "1", "-j", CHAIN]).await?;
            }
        }
        Ok(())
    }

    async fn cleanup_chain_if_empty(&self, state: &State) -> Result<()> {
        if !state.policies.is_empty() {
            return Ok(());
        }
        for tool in ["iptables", "ip6tables"] {
            let existing = command_output(tool, &["-S", CHAIN]).await;
            let Ok(existing) = existing else { continue };
            if !existing.contains(CHAIN_MARKER) {
                continue;
            }
            while command(tool, &["-C", "FORWARD", "-j", CHAIN]).await.is_ok() {
                command(tool, &["-D", "FORWARD", "-j", CHAIN]).await?;
            }
            command(tool, &["-F", CHAIN]).await?;
            command(tool, &["-X", CHAIN]).await?;
        }
        Ok(())
    }

    fn save(&self, state: &State) -> Result<()> {
        save_state(&self.path, state)
    }
}

fn validate_policy(policy: &Policy) -> Result<()> {
    if !valid_policy_id(&policy.id)
        || policy.vm_id.is_empty()
        || policy.vm_id.len() > 200
        || policy.vm_id.chars().any(char::is_control)
    {
        bail!("invalid connection-limit policy target");
    }
    crate::model::VmId::parse(&policy.vm_id).context("invalid Runman VM UUID")?;
    uuid::Uuid::parse_str(&policy.instance_id).context("invalid instance generation identity")?;
    if !(100..=10_000).contains(&policy.max_connections) {
        bail!("max_connections must be between 100 and 10000");
    }
    let remaining = policy.expires_at.saturating_sub(now());
    if !(60..=3600).contains(&remaining) {
        bail!("connection-limit lease must be between 60 and 3600 seconds");
    }
    Ok(())
}

fn validate_ips(raw: &[String]) -> Result<Vec<String>> {
    let mut ips = raw
        .iter()
        .map(|s| s.parse::<IpAddr>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if ips.iter().any(|ip| match ip {
        IpAddr::V4(ip) => {
            ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_link_local()
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
        }
    }) {
        bail!("instance address is not a usable unicast address");
    }
    ips.sort();
    ips.dedup();
    Ok(ips.into_iter().map(|ip| ip.to_string()).collect())
}

fn valid_policy_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn load_state(path: &Path) -> Result<State> {
    match std::fs::read(path) {
        Ok(data) => {
            let state: State =
                serde_json::from_slice(&data).context("decode connection-limit state")?;
            for policy in &state.policies {
                if !valid_policy_id(&policy.id)
                    || policy.vm_id.is_empty()
                    || policy.max_connections < 100
                {
                    bail!("persisted connection-limit state contains an invalid policy");
                }
            }
            Ok(state)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(e.into()),
    }
}

fn save_state(path: &Path, state: &State) -> Result<()> {
    let dir = path
        .parent()
        .context("connection-limit state has no parent directory")?;
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let data = serde_json::to_vec_pretty(state)?;
    let temp = dir.join(format!(".connlimit-{}.tmp", uuid::Uuid::new_v4()));
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        use std::io::Write;
        file.write_all(&data)?;
        file.sync_all()?;
    }
    std::fs::rename(&temp, path).with_context(|| format!("replace {}", path.display()))
}

async fn command(tool: &str, args: &[impl AsRef<std::ffi::OsStr>]) -> Result<()> {
    let mut full = vec![
        "-w".to_owned(),
        "5".to_owned(),
        "-t".to_owned(),
        "filter".to_owned(),
    ];
    full.extend(
        args.iter()
            .map(|v| v.as_ref().to_string_lossy().into_owned()),
    );
    let output = Command::new(tool)
        .args(&full)
        .output()
        .await
        .with_context(|| format!("run {tool}"))?;
    if !output.status.success() {
        bail!(
            "{tool} {} failed: {}",
            full.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

async fn command_output(tool: &str, args: &[impl AsRef<std::ffi::OsStr>]) -> Result<String> {
    let mut full = vec![
        "-w".to_owned(),
        "5".to_owned(),
        "-t".to_owned(),
        "filter".to_owned(),
    ];
    full.extend(
        args.iter()
            .map(|v| v.as_ref().to_string_lossy().into_owned()),
    );
    let output = Command::new(tool)
        .args(&full)
        .output()
        .await
        .with_context(|| format!("run {tool}"))?;
    if !output.status.success() {
        bail!(
            "{tool} {} failed: {}",
            full.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub async fn reconcile_loop<F, Fut>(manager: std::sync::Arc<Manager>, resolve: F)
where
    F: Fn(String) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Target>> + Send + 'static,
{
    loop {
        if let Err(e) = manager.reconcile(resolve.clone()).await {
            warn!("connection-limit reconciliation incomplete: {e:#}");
        }
        manager.wait_for_reconcile().await;
    }
}

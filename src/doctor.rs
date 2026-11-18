//! Read-only node checks. The report never serializes the configuration.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};
use tokio::process::Command;

use crate::config::{BackendKind, Config};

const TIMEOUT: Duration = Duration::from_secs(5);

async fn succeeds(program: &str, args: &[&str]) -> bool {
    let mut command = Command::new(program);
    command.args(args).kill_on_drop(true);
    tokio::time::timeout(TIMEOUT, command.output())
        .await
        .is_ok_and(|result| result.is_ok_and(|output| output.status.success()))
}

pub async fn report(config: &Config) -> Result<Value> {
    let node_service = succeeds(
        "systemctl",
        &["is-active", "--quiet", "runman-agent.service"],
    );
    let platform = async {
        if config.token.is_empty() {
            return "standalone";
        }
        let Ok(endpoint) = crate::platform::platform_endpoint(config, TIMEOUT) else {
            return "invalid_endpoint";
        };
        if tokio::time::timeout(TIMEOUT, endpoint.connect())
            .await
            .is_ok_and(|result| result.is_ok())
        {
            "transport_reachable"
        } else {
            "transport_unreachable"
        }
    };
    let rfw = async {
        let address = config.rfw_addr.parse::<std::net::SocketAddr>()?;
        if !address.ip().is_loopback() {
            return Ok::<_, anyhow::Error>("non_loopback");
        }
        let url = format!("http://{address}/api/status");
        if succeeds("curl", &["-q", "--noproxy", "*", "-fsS", &url]).await {
            Ok("reachable")
        } else {
            Ok("unreachable")
        }
    };
    let network = async {
        if config.backend != BackendKind::Container {
            return Value::Null;
        }
        let net = &config.network;
        let (bridge, nft_table) = tokio::join!(
            succeeds("ip", &["link", "show", "dev", &net.bridge]),
            succeeds("nft", &["list", "table", "inet", &net.nft_table]),
        );
        json!({
            "bridge_present": bridge,
            "nft_table_readable": nft_table,
            "ipv6_mode": net.ipv6_mode,
            "ipv6_pool_size": net.ipv6_pool.len(),
        })
    };
    let (node_service, platform, rfw, network) = tokio::join!(node_service, platform, rfw, network);
    Ok(json!({
        "version": crate::updater::version(),
        "backend": config.backend,
        "service_active": node_service,
        "cgroup_v2": Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "platform": platform,
        "rfw_api": rfw?,
        "network": network,
    }))
}

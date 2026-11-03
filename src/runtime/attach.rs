//! Plugging an instance's network namespace into the host bridge. Used by the
//! supervisor at boot and by the agent to repair a running instance whose
//! veth disappeared. Synchronous on purpose: the supervisor has no runtime.

use std::process::Command;

use anyhow::{Result, bail};

use super::spec::NetSpec;

/// Create the veth pair with `eth0` inside the network namespace of `pid`,
/// plug the host end into the bridge as an isolated port and apply limits.
/// The veth disappears together with the namespace when the instance stops.
/// A leftover interface with the same host name is replaced.
pub fn attach(net: &NetSpec, pid: i32) -> Result<()> {
    let hif = net.host_if.as_str();
    let _ = Command::new("ip")
        .args(["link", "del", hif])
        .stderr(std::process::Stdio::null())
        .status();
    let pid = pid.to_string();
    sh(&[
        "ip", "link", "add", hif, "type", "veth", "peer", "name", "eth0", "address", &net.mac,
        "netns", &pid,
    ])?;
    sh(&["ip", "link", "set", hif, "master", &net.bridge])?;
    sh(&["bridge", "link", "set", "dev", hif, "isolated", "on"])?;
    if net.isolated {
        sh(&["ip", "link", "set", "dev", hif, "down"])?;
    } else {
        sh(&["ip", "link", "set", "dev", hif, "up"])?;
    }
    if net.bandwidth_mbps > 0 {
        let rate = format!("{}mbit", net.bandwidth_mbps);
        // Download (host -> instance): shaped on the host end's egress.
        sh(&[
            "tc",
            "qdisc",
            "replace",
            "dev",
            hif,
            "root",
            "cake",
            "bandwidth",
            &rate,
        ])?;
        // Upload (instance -> host): ingress traffic is redirected through an
        // IFB device and shaped there too (policing makes TCP collapse far
        // below the limit). Both live outside the instance's namespace, so
        // its root cannot lift them.
        let ifb = ifb_name(hif);
        let _ = Command::new("ip")
            .args(["link", "del", &ifb])
            .stderr(std::process::Stdio::null())
            .status();
        sh(&["ip", "link", "add", &ifb, "type", "ifb"])?;
        sh(&["ip", "link", "set", &ifb, "up"])?;
        sh(&[
            "tc",
            "qdisc",
            "replace",
            "dev",
            &ifb,
            "root",
            "cake",
            "bandwidth",
            &rate,
        ])?;
        sh(&[
            "tc", "qdisc", "replace", "dev", hif, "handle", "ffff:", "ingress",
        ])?;
        sh(&[
            "tc", "filter", "replace", "dev", hif, "parent", "ffff:", "matchall", "action",
            "mirred", "egress", "redirect", "dev", &ifb,
        ])?;
    }
    Ok(())
}

/// Read the administrative `IFF_UP` state of a host-side veth.
pub fn host_link_up(host_if: &str) -> Result<bool> {
    validate_host_if(host_if)?;
    let flags = std::fs::read_to_string(format!("/sys/class/net/{host_if}/flags"))?;
    let flags = flags.trim().strip_prefix("0x").unwrap_or(flags.trim());
    let flags = u32::from_str_radix(flags, 16)?;
    Ok(flags & libc::IFF_UP as u32 != 0)
}

/// Change only a Runman-managed host-side veth and verify the kernel readback.
pub fn set_host_link_up(host_if: &str, up: bool) -> Result<()> {
    validate_host_if(host_if)?;
    let state = if up { "up" } else { "down" };
    sh(&["ip", "link", "set", "dev", host_if, state])?;
    if host_link_up(host_if)? != up {
        bail!("host interface {host_if} link-state readback mismatch");
    }
    Ok(())
}

fn validate_host_if(host_if: &str) -> Result<()> {
    if host_if.is_empty()
        || host_if.len() > 15
        || !host_if
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        bail!("invalid Runman host interface name");
    }
    Ok(())
}

fn ifb_name(host_if: &str) -> String {
    format!("{host_if}i")
}

/// The veth goes away with the namespace; the IFB device does not.
pub fn detach(net: &NetSpec) {
    let _ = Command::new("ip")
        .args(["link", "del", &ifb_name(&net.host_if)])
        .stderr(std::process::Stdio::null())
        .status();
}

fn sh(argv: &[&str]) -> Result<()> {
    let out = Command::new(argv[0]).args(&argv[1..]).output()?;
    if !out.status.success() {
        bail!(
            "{} failed: {}",
            argv.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

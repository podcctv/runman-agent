//! Local CLI for the running container agent.

use std::io::{self, IsTerminal, Write};

use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;
use serde_json::{Value, json};
use tokio::process::Command;

use crate::model::VmId;

const SOCKET: &str = "/run/runman-agent-cli/manage.sock";

#[cfg(target_os = "linux")]
pub fn bind() -> Result<(tokio::net::UnixListener, std::fs::File)> {
    use std::fs::{self, DirBuilder, OpenOptions};
    use std::os::unix::fs::{
        DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
    };
    use std::path::Path;

    let path = Path::new(SOCKET);
    let parent = path.parent().expect("management socket has a parent");
    if let Err(error) = DirBuilder::new().mode(0o700).create(parent)
        && error.kind() != io::ErrorKind::AlreadyExists
    {
        return Err(error).context("create instance CLI directory");
    }
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o777 == 0o700,
        "expected a root-owned 0700 directory at {}",
        parent.display()
    );
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(parent.join("manage.lock"))?;
    lock.try_lock()
        .context("another agent holds the instance management socket")?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == 0 => fs::remove_file(path)?,
        Ok(_) => bail!("unexpected file at {SOCKET}"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok((listener, lock))
}

#[derive(Subcommand)]
pub enum Action {
    /// Show all instances.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show configuration, addresses and forwards for an instance.
    Inspect {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Show recent console output.
    Logs {
        id: String,
    },
    Start {
        id: String,
    },
    Stop {
        id: String,
        #[arg(long)]
        force: bool,
    },
    Restart {
        id: String,
    },
    /// Select and manage an instance interactively.
    Menu,
    /// Create and start a system container on a standalone node.
    Create {
        #[arg(long)]
        image: String,
        #[arg(long, default_value_t = 1)]
        cpus: u32,
        #[arg(long, default_value_t = 512)]
        memory_mib: u64,
        #[arg(long, default_value_t = 10)]
        disk_gib: u64,
        #[arg(long, default_value_t = 0)]
        bandwidth_mbps: u32,
    },
    /// List or modify instance port forwards.
    Port {
        #[command(subcommand)]
        action: PortAction,
    },
    /// Back up a stopped instance on a standalone node.
    Backup {
        id: String,
    },
    /// List available local backups.
    Backups,
    /// Restore a local backup to a new, stopped instance.
    Restore {
        backup_id: String,
    },
}

#[derive(Subcommand)]
pub enum PortAction {
    List {
        id: String,
    },
    Add {
        id: String,
        #[arg(long, default_value = "tcp", value_parser = ["tcp", "udp"])]
        protocol: String,
        #[arg(long, default_value_t = 0)]
        host_port: u16,
        #[arg(long)]
        guest_port: u16,
    },
    Remove {
        id: String,
        #[arg(long, default_value = "tcp", value_parser = ["tcp", "udp"])]
        protocol: String,
        #[arg(long)]
        host_port: u16,
    },
}

async fn request(method: &str, path: &str, body: Option<Value>) -> Result<Vec<u8>> {
    let mut curl = Command::new("curl");
    curl.kill_on_drop(true).args([
        "-q",
        "--noproxy",
        "*",
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--connect-timeout",
        "5",
        "--unix-socket",
        SOCKET,
        "--request",
        method,
    ]);
    if let Some(body) = body {
        curl.args([
            "--header",
            "Content-Type: application/json",
            "--data-binary",
        ])
        .arg(body.to_string());
    }
    let out = curl
        .arg(format!("http://localhost{path}"))
        .output()
        .await
        .context("run curl for the local agent socket")?;
    if !out.status.success() {
        if let Ok(body) = serde_json::from_slice::<Value>(&out.stdout)
            && let Some(message) = body["error"].as_str()
        {
            bail!("{message}");
        }
        bail!(
            "could not reach the agent at {SOCKET}; check the service and run with sudo ({})",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

async fn inventory() -> Result<Vec<Value>> {
    Ok(serde_json::from_slice(
        &request("GET", "/v1/instances", None).await?,
    )?)
}

fn field<'a>(row: &'a Value, key: &str) -> &'a str {
    row[key]
        .as_str()
        .filter(|value| !value.is_empty())
        .unwrap_or("-")
}

fn addresses(row: &Value, key: &str) -> String {
    row[key]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

fn table(rows: &[Value], numbered: bool) {
    if rows.is_empty() {
        println!("No instances.");
        return;
    }
    println!(
        "{:3} {:36} {:20} {:9} {:12} ADDRESSES",
        "", "ID", "HOSTNAME", "STATUS", "IMAGE"
    );
    for (i, row) in rows.iter().enumerate() {
        let number = if numbered {
            (i + 1).to_string()
        } else {
            String::new()
        };
        println!(
            "{number:3} {:36} {:20} {:9} {:12} {}",
            field(row, "id"),
            field(row, "hostname"),
            field(row, "status"),
            field(row, "os_image"),
            [addresses(row, "ips"), addresses(row, "dedicated")]
                .into_iter()
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn inspect(row: &Value) {
    println!(
        "{}  {}  ({})",
        field(row, "hostname"),
        field(row, "id"),
        field(row, "status")
    );
    println!(
        "Image {}  CPU {}  Memory {} MiB  Disk {} GiB  Bandwidth {} Mbps",
        field(row, "os_image"),
        row["cpu"],
        row["ram_mb"],
        row["disk_gb"],
        row["bandwidth_mbps"]
    );
    println!("Addresses {}", addresses(row, "ips"));
    println!("Dedicated addresses {}", addresses(row, "dedicated"));
    show_ports(row);
}

fn show_ports(row: &Value) {
    println!("Port forwards");
    for port in row["forwards"].as_array().into_iter().flatten() {
        println!(
            "  {}/{} -> {}",
            port["host_port"],
            field(port, "proto"),
            port["guest_port"]
        );
    }
}

async fn instance(id: &str) -> Result<Value> {
    let id = VmId::parse(id)?;
    inventory()
        .await?
        .into_iter()
        .find(|row| row["id"] == id.as_str())
        .with_context(|| format!("instance {id} not found"))
}

async fn send(method: &str, path: &str, body: Option<Value>) -> Result<()> {
    let bytes = request(method, path, body).await?;
    print_json(&serde_json::from_slice::<Value>(&bytes)?)
}

async fn power(id: &str, action: &str) -> Result<()> {
    let id = VmId::parse(id)?;
    send(
        "POST",
        &format!("/v1/instances/{id}/power"),
        Some(json!({ "action": action })),
    )
    .await
}

async fn logs(id: &str) -> Result<()> {
    let id = VmId::parse(id)?;
    let bytes = request("GET", &format!("/v1/instances/{id}/console-log"), None).await?;
    if io::stdout().is_terminal() {
        let safe: String = String::from_utf8_lossy(&bytes)
            .chars()
            .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
            .collect();
        print!("{safe}");
    } else {
        io::stdout().write_all(&bytes)?;
    }
    Ok(())
}

fn prompt(label: &str) -> Result<Option<String>> {
    print!("{label} ");
    io::stdout().flush()?;
    let mut value = String::new();
    if io::stdin().read_line(&mut value)? == 0 {
        return Ok(None);
    }
    Ok(Some(value.trim().to_owned()))
}

async fn menu() -> Result<()> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "interactive mode requires a terminal; use 'instance list --json' for scripts"
    );
    loop {
        let rows = inventory().await?;
        table(&rows, true);
        let Some(choice) = prompt("Instance number, r to refresh, q to quit:")? else {
            break;
        };
        match choice.as_str() {
            "q" => break,
            "r" => continue,
            _ => {}
        }
        let Some(row) = choice
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|index| rows.get(index))
        else {
            eprintln!("Choose an instance number.");
            continue;
        };
        let id = field(row, "id");
        let Some(action) =
            prompt("1 Info  2 Logs  3 Start  4 Stop  5 Restart  6 Ports  7 Backup  Enter Back:")?
        else {
            break;
        };
        let response = match action.as_str() {
            "1" => {
                inspect(row);
                Ok(())
            }
            "2" => logs(id).await,
            "3" => power(id, "start").await,
            "4" | "5" => {
                let operation = if action == "4" { "stop" } else { "restart" };
                if prompt(&format!("{operation} {id}? [y/N]"))?.as_deref() != Some("y") {
                    continue;
                }
                power(id, operation).await
            }
            "6" => {
                show_ports(row);
                Ok(())
            }
            "7" => backup(id).await,
            "" => continue,
            _ => {
                eprintln!("Unknown action.");
                continue;
            }
        };
        if let Err(error) = response {
            eprintln!("{error:#}");
        }
        if prompt("Press Enter to return to the list.")?.is_none() {
            break;
        }
    }
    Ok(())
}

async fn backup(id: &str) -> Result<()> {
    let id = VmId::parse(id)?;
    send("POST", &format!("/v1/instances/{id}/backup"), None).await
}

pub async fn run(action: Option<Action>) -> Result<()> {
    match action.unwrap_or(Action::Menu) {
        Action::Menu => menu().await,
        Action::List { json } => {
            let rows = inventory().await?;
            if json {
                print_json(&rows)
            } else {
                table(&rows, false);
                Ok(())
            }
        }
        Action::Inspect { id, json } => {
            let row = instance(&id).await?;
            if json {
                print_json(&row)
            } else {
                inspect(&row);
                Ok(())
            }
        }
        Action::Logs { id } => logs(&id).await,
        Action::Start { id } => power(&id, "start").await,
        Action::Stop { id, force } => power(&id, if force { "force_stop" } else { "stop" }).await,
        Action::Restart { id } => power(&id, "restart").await,
        Action::Backup { id } => backup(&id).await,
        Action::Backups => send("GET", "/v1/backups", None).await,
        Action::Restore { backup_id } => {
            let id = VmId::parse(&backup_id)?;
            send("POST", &format!("/v1/backups/{id}/restore"), None).await
        }
        Action::Create {
            image,
            cpus,
            memory_mib,
            disk_gib,
            bandwidth_mbps,
        } => {
            send(
                "POST",
                "/v1/instances",
                Some(json!({
                    "os_image": image, "cpu": cpus, "ram_mb": memory_mib, "disk_gb": disk_gib,
                    "bandwidth_mbps": bandwidth_mbps,
                })),
            )
            .await
        }
        Action::Port { action } => match action {
            PortAction::List { id } => print_json(&instance(&id).await?["forwards"]),
            PortAction::Add {
                id,
                protocol,
                host_port,
                guest_port,
            } => {
                let id = VmId::parse(&id)?;
                send(
                    "POST",
                    &format!("/v1/instances/{id}/forwards"),
                    Some(json!({
                        "proto": protocol, "host_port": host_port, "guest_port": guest_port,
                    })),
                )
                .await
            }
            PortAction::Remove {
                id,
                protocol,
                host_port,
            } => {
                let id = VmId::parse(&id)?;
                send(
                    "DELETE",
                    &format!("/v1/instances/{id}/forwards/{protocol}/{host_port}"),
                    None,
                )
                .await
            }
        },
    }
}

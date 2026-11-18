//! Execution of platform commands.
//!
//! - Commands for the same instance run strictly one after another.
//! - The platform persists commands and may replay a `command_id` after a
//!   reconnect. A replay of a running command is ignored (its result is sent
//!   when it finishes); a replay of a finished command re-sends the cached
//!   result instead of executing it twice.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use prost::Message;
use rusqlite::{Connection, params};
use tracing::{info, warn};

use super::Link;
use crate::backend::Services;
use crate::model::{InstanceSpec, L4Proto, PortForward, VmId, port, validate_password};
use crate::proto::agent_envelope::Payload as Up;
use crate::proto::platform_envelope::Payload as Down;
use crate::proto::{self, CommandResult};

const RESULT_TTL: Duration = Duration::from_secs(3600);
const CACHE_SOFT_LIMIT: usize = 1024;

enum Entry {
    Running,
    Done(Box<Up>, Instant),
}

pub struct CommandRunner {
    services: Services,
    link: Link,
    cache: Mutex<HashMap<String, Entry>>,
    vm_locks: Mutex<HashMap<VmId, Arc<tokio::sync::Mutex<()>>>>,
    journal: Option<PathBuf>,
    platform: String,
}

impl CommandRunner {
    pub fn new(
        services: Services,
        link: Link,
        journal: Option<PathBuf>,
        platform: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            services,
            link,
            cache: Mutex::default(),
            vm_locks: Mutex::default(),
            journal,
            platform,
        })
    }

    /// Accept a command from the stream; execution happens in the background.
    pub async fn submit(self: &Arc<Self>, command_id: String, payload: Option<Down>) {
        if !command_id.is_empty() {
            let cached = {
                let mut cache = self.cache.lock().unwrap();
                match cache.get(&command_id) {
                    Some(Entry::Running) => return,
                    Some(Entry::Done(reply, _)) => Some((**reply).clone()),
                    None => {
                        prune(&mut cache);
                        cache.insert(command_id.clone(), Entry::Running);
                        None
                    }
                }
            };
            if let Some(reply) = cached {
                info!("command {command_id} replayed; re-sending cached result");
                self.link.send(reply).await;
                return;
            }
        }

        let this = self.clone();
        tokio::spawn(async move {
            let reply = this.execute_once(&command_id, payload).await;
            if !command_id.is_empty() {
                this.cache.lock().unwrap().insert(
                    command_id.clone(),
                    Entry::Done(Box::new(reply.clone()), Instant::now()),
                );
            }
            if !this.link.send(reply).await {
                warn!("command {command_id}: no platform connection; result kept for replay");
            }
        });
    }

    async fn execute_once(&self, id: &str, payload: Option<Down>) -> Up {
        let Some(path) = self.journal.as_ref().filter(|_| {
            !id.is_empty()
                && matches!(
                    payload,
                    Some(
                        Down::CreateVm(_)
                            | Down::ReinstallVm(_)
                            | Down::DeleteVm(_)
                            | Down::RestartVm(_)
                            | Down::StartVm(_)
                            | Down::StopVm(_)
                            | Down::ResetPassword(_)
                            | Down::SetPortFwd(_)
                            | Down::DelPortFwd(_)
                    )
                )
        }) else {
            return self.execute(id, payload).await;
        };
        let connection = match open_journal(path) {
            Ok(connection) => connection,
            Err(error) => return journal_error(id, error, "open"),
        };
        match claim(&connection, &self.platform, id) {
            Ok(Claim::New) => {}
            Ok(Claim::Finished(reply)) => return Up::CmdResult(reply),
            Ok(Claim::Interrupted) => {
                return result(
                    id,
                    Err(anyhow::anyhow!(
                        "previous execution was interrupted; inspect the instance before retrying under a new command ID"
                    )),
                );
            }
            Err(error) => return journal_error(id, error, "claim"),
        }
        let reply = self.execute(id, payload).await;
        if let Up::CmdResult(completed) = &reply
            && let Err(error) = connection.execute(
                "UPDATE commands SET result = ?3 WHERE platform = ?1 AND id = ?2",
                params![self.platform, id, completed.encode_to_vec()],
            )
        {
            return journal_error(id, error.into(), "record result");
        }
        reply
    }

    async fn execute(&self, command_id: &str, payload: Option<Down>) -> Up {
        let kind = payload.as_ref().map_or("empty", kind_name);
        // Handled outside the lifecycle path: it answers with its own message.
        if let Some(Down::GetPortFwds(q)) = &payload {
            match self.list_port_forwards(&q.vm_id).await {
                Ok(entries) => {
                    return Up::PortFwdList(proto::PortForwardList {
                        command_id: command_id.to_owned(),
                        entries,
                    });
                }
                Err(e) => return result(command_id, Err(e)),
            }
        }

        let started = Instant::now();
        let res = self.run(payload).await;
        match &res {
            Ok(()) => info!(
                "command {command_id} ({kind}) ok in {:?}",
                started.elapsed()
            ),
            Err(e) => warn!("command {command_id} ({kind}) failed: {e:#}"),
        }
        result(command_id, res)
    }

    async fn run(&self, payload: Option<Down>) -> Result<()> {
        let s = &self.services;
        match payload {
            Some(Down::CreateVm(c)) => {
                let spec = InstanceSpec::from_create(&c)?;
                let _g = self.lock_vm(&spec.vm_id).await;
                s.instances.create(&spec).await?;
                crate::backend::ensure_ssh_forward(s.port_forwards.as_ref(), &spec.vm_id).await;
                Ok(())
            }
            Some(Down::ReinstallVm(c)) => {
                let spec = InstanceSpec::from_reinstall(&c)?;
                let _g = self.lock_vm(&spec.vm_id).await;
                s.instances.reinstall(&spec).await?;
                crate::backend::ensure_ssh_forward(s.port_forwards.as_ref(), &spec.vm_id).await;
                Ok(())
            }
            Some(Down::StartVm(c)) => {
                let id = VmId::parse(&c.vm_id)?;
                let _g = self.lock_vm(&id).await;
                s.instances.start(&id).await
            }
            Some(Down::StopVm(c)) => {
                let id = VmId::parse(&c.vm_id)?;
                let _g = self.lock_vm(&id).await;
                s.instances.stop(&id, c.force).await
            }
            Some(Down::RestartVm(c)) => {
                let id = VmId::parse(&c.vm_id)?;
                let _g = self.lock_vm(&id).await;
                s.instances.restart(&id).await
            }
            Some(Down::DeleteVm(c)) => {
                let id = VmId::parse(&c.vm_id)?;
                let _g = self.lock_vm(&id).await;
                s.instances.delete(&id).await?;
                s.port_forwards.remove_all(&id).await
            }
            Some(Down::ResetPassword(c)) => {
                let id = VmId::parse(&c.vm_id)?;
                validate_password(&c.new_password)?;
                let _g = self.lock_vm(&id).await;
                s.instances.reset_password(&id, &c.new_password).await
            }
            Some(Down::SetPortFwd(c)) => {
                s.port_forwards
                    .add(PortForward {
                        vm_id: VmId::parse(&c.vm_id)?,
                        proto: L4Proto::from_proto(c.protocol)?,
                        host_port: port(c.host_port, "host_port")?,
                        guest_port: port(c.guest_port, "guest_port")?,
                        description: c.description,
                    })
                    .await
            }
            Some(Down::DelPortFwd(c)) => {
                let id = VmId::parse(&c.vm_id)?;
                let proto = L4Proto::from_proto(c.protocol)?;
                s.port_forwards
                    .remove(&id, proto, port(c.host_port, "host_port")?)
                    .await
            }
            Some(other) => bail!("unsupported command {}", kind_name(&other)),
            None => bail!("empty or unknown command payload"),
        }
    }

    async fn list_port_forwards(&self, vm_id: &str) -> Result<Vec<proto::PortForwardEntry>> {
        let id = VmId::parse(vm_id)?;
        let rules = self.services.port_forwards.list(Some(&id)).await?;
        Ok(rules.iter().map(PortForward::to_proto).collect())
    }

    async fn lock_vm(&self, id: &VmId) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.vm_locks.lock().unwrap();
            if locks.len() > CACHE_SOFT_LIMIT {
                locks.retain(|_, l| Arc::strong_count(l) > 1);
            }
            locks.entry(id.clone()).or_default().clone()
        };
        lock.lock_owned().await
    }
}

fn open_journal(path: &Path) -> Result<Connection> {
    let connection = Connection::open(path)?;
    connection.execute_batch(
        "PRAGMA synchronous = FULL;
         CREATE TABLE IF NOT EXISTS commands (
             platform TEXT NOT NULL,
             id TEXT NOT NULL,
             result BLOB,
             PRIMARY KEY (platform, id)
         );",
    )?;
    Ok(connection)
}

enum Claim {
    New,
    Finished(CommandResult),
    Interrupted,
}

fn claim(connection: &Connection, platform: &str, id: &str) -> Result<Claim> {
    let inserted = connection.execute(
        "INSERT INTO commands (platform, id) VALUES (?1, ?2)
         ON CONFLICT(platform, id) DO NOTHING",
        params![platform, id],
    )?;
    if inserted == 1 {
        return Ok(Claim::New);
    }
    let recorded: Option<Vec<u8>> = connection.query_row(
        "SELECT result FROM commands WHERE platform = ?1 AND id = ?2",
        params![platform, id],
        |row| row.get(0),
    )?;
    match recorded {
        Some(bytes) => Ok(Claim::Finished(CommandResult::decode(bytes.as_slice())?)),
        None => Ok(Claim::Interrupted),
    }
}

fn journal_error(id: &str, error: anyhow::Error, operation: &str) -> Up {
    warn!("command {id}: could not {operation} in persistent command journal: {error:#}");
    result(
        id,
        Err(anyhow::anyhow!(
            "persistent command journal error; inspect the node before retrying"
        )),
    )
}

fn prune(cache: &mut HashMap<String, Entry>) {
    if cache.len() >= CACHE_SOFT_LIMIT {
        cache.retain(|_, e| match e {
            Entry::Running => true,
            Entry::Done(_, at) => at.elapsed() < RESULT_TTL,
        });
    }
}

fn result(command_id: &str, res: Result<()>) -> Up {
    Up::CmdResult(CommandResult {
        command_id: command_id.to_owned(),
        success: res.is_ok(),
        error: res.err().map(|e| format!("{e:#}")).unwrap_or_default(),
        data: Vec::new(),
    })
}

fn kind_name(p: &Down) -> &'static str {
    match p {
        Down::CreateVm(_) => "create_vm",
        Down::StartVm(_) => "start_vm",
        Down::StopVm(_) => "stop_vm",
        Down::RestartVm(_) => "restart_vm",
        Down::DeleteVm(_) => "delete_vm",
        Down::ReinstallVm(_) => "reinstall_vm",
        Down::ResetPassword(_) => "reset_password",
        Down::SetPortFwd(_) => "set_port_fwd",
        Down::DelPortFwd(_) => "del_port_fwd",
        Down::GetPortFwds(_) => "get_port_fwds",
        Down::Ping(_) => "ping",
        Down::ConsoleOpen(_) => "console_open",
        Down::ConsoleInput(_) => "console_input",
        Down::ConsoleResize(_) => "console_resize",
        Down::ConsoleClose(_) => "console_close",
        Down::WgSyncResponse(_) => "wg_sync_response",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_distinguishes_completed_and_interrupted_replays() -> Result<()> {
        let path =
            std::env::temp_dir().join(format!("runman-commands-{}.db", uuid::Uuid::new_v4()));
        let check = (|| {
            let first = open_journal(&path)?;
            assert!(matches!(claim(&first, "platform", "done")?, Claim::New));
            assert!(matches!(claim(&first, "platform", "pending")?, Claim::New));
            let reply = CommandResult {
                command_id: "done".into(),
                success: true,
                ..Default::default()
            };
            first.execute(
                "UPDATE commands SET result = ?1 WHERE id = 'done'",
                [reply.encode_to_vec()],
            )?;
            drop(first);
            let reopened = open_journal(&path)?;
            assert!(matches!(
                claim(&reopened, "platform", "done")?,
                Claim::Finished(recorded) if recorded == reply
            ));
            assert!(matches!(
                claim(&reopened, "platform", "pending")?,
                Claim::Interrupted
            ));
            assert!(matches!(claim(&reopened, "other", "done")?, Claim::New));
            Ok(())
        })();
        let _ = std::fs::remove_file(&path);
        check
    }
}

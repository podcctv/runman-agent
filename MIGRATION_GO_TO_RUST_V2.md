# Go Agent to Rust v2 migration plan

Rust v2 is a parallel major line. The Go `main` branch and its `continuous`
release remain the production line until each migration has a verified
cutover. Rust v2 publishes to `continuous-rs`; it never replaces that Go asset.

## Compatibility boundary

Rust v2 does not read or convert the Go configuration at
`/opt/narwhal-agent/config.json`, the Go `agent.db`, or Go-managed Podman and
Incus instances. It uses `/etc/runman-agent/config.toml`, its own data under
`/var/lib/runman-agent`, and a different system-container runtime. A guest or
database copy is not a supported in-place migration.

The installer checks for a Go installation and stops before changing the
host. Do not remove that guard or point the Go updater at `continuous-rs`.

## Recommended staged cutover

1. Inventory the old host: VM IDs, guest disks and attached volumes, addresses,
   forwards, dedicated IPs, RFW rules, active temporary connection limits,
   tokens, and service configuration. Take application-consistent backups and
   prove that representative guest data can be restored.
2. Confirm the platform can register a separate Rust v2 canary node without
   replacing the Go node that owns the production token. If it cannot, stop
   here and add a platform-side staging identity/mapping first.
3. Install Rust v2 on a fresh Debian/Ubuntu host with an isolated canary
   identity. Recreate a small workload from verified application backups;
   restore forwards, dedicated IP bindings, and policies explicitly.
4. Verify guest data, network reachability, inbound services, outbound
   connectivity, RFW readback, Watcher firewall actions, connlimit apply,
   expiry, and removal after stop/delete/recreate.
5. Schedule a maintenance window. Freeze new sales and changes, take final
   backups, drain traffic, and migrate workloads in measured batches. Keep the
   old Go host intact and disconnected from the platform during the Rust
   ownership window so both agents cannot reconcile the same node identity.
6. Roll back by draining Rust v2, restoring the old Go host and its original
   state from the verified backup, and reconnecting only the Go identity.
   Do not run both agents against one platform identity during rollback.

## RFW and connection-limit state

Rust v2 stores its desired RFW policy and rule ownership in
`/var/lib/runman-agent/host-firewall.json`. Watcher connects over the
root-only Unix socket `/run/narwhal-agent/firewall.sock`. Temporary connection
limits are stored in `/var/lib/runman-agent/connlimit.json` and managed through
`/run/narwhal-agent/connlimit.sock`. Limits bind to the Rust instance UUID and
generation; a replacement instance cannot inherit an old lease. The local
connlimit API accepts the managed VM UUID as `container_name`; a caller can
query `/v1/connlimit/target` to obtain the current generation, or omit
`instance_id` during apply and use the identity returned by the successful
response. Existing Incus identities do not identify Rust instances. Reapply
active Watcher policies after a cutover instead of copying Go runtime state.

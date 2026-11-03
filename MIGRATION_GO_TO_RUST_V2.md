# Go Agent to Rust v2 migration

Rust v2 is a parallel major line. Go `main` and its `continuous` release remain
available; Rust publishes separately to `continuous-rs`. The Go installer
offers menu item 15, which downloads the Rust installer and starts the same
`--migrate-go` flow.

## Supported source and retained settings

The migration supports the standard Go Podman and Incus container backends.
Preflight reads the Go JSON config, takes an SQLite online backup, verifies the
live backend objects, and validates every item before stopping the Go agent.
After confirmation it stops Go, takes a final config/database/live-state
snapshot, then stops the old guests.

It rebuilds clean Rust containers and retains:

- the platform host ID and token, panel user/password hash and listen address;
- each VM UUID, CPU, memory, disk and bandwidth limits;
- Alpine or Debian OS family and whether the guest was running;
- supported TCP/UDP host-to-guest port forwards;
- the supported host IPv6 mode/prefix and RFW API address.

Generated root passwords are written to a root-only file in the migration
backup directory. The operator must retrieve them there after migration.

## Data that is intentionally lost

This is a destructive clean rebuild. Successful commit deletes old Podman or
Incus guest root filesystems. Guest files, installed applications, databases,
traffic history, per-guest IPv4/IPv6 addresses, WireGuard bindings, dedicated
addresses, custom images, and mounted-volume attachments are not migrated.
The old host packages and container images are left in place. Incus host-path
mounts and other unsupported backend-specific settings are not recreated in
Rust.

Only standard Alpine and Debian image families are accepted. Unknown images,
invalid resource settings, unsupported Go config, missing records, occupied
ports, and failed Rust checks abort before old guests are purged.

## Rollback boundary

Before the destructive cleanup phase, an installer failure stops the partial
Rust service, removes its managed state, restores the Go config/service state,
and restarts the guests that were running before migration. The snapshot stays
under `/var/backups/runman-go-to-rust-v2.*` with mode 0700.

The installer marks migration committed only after the Rust service, panel,
instance UUID/run-state inventory, and port-forward records pass checks. It
then removes old guest root filesystems. If that cleanup partially fails, Rust
remains active and cleanup is reported as pending; deleted Go guests cannot be
restored automatically. Power loss, hardware faults, and every package change
cannot be guaranteed reversible. Do not describe this process as 100% rollback
guaranteed.

The Go agent is stopped and disabled before Rust starts so both agents never
reconcile the same platform identity concurrently. RFW is not migrated or
reinstalled by this flow; its existing host service remains outside guest
cleanup.

## Podman Watcher compatibility

The root-only Runman Unix socket exposes read-only inventory and fresh
connection evidence, plus existing host RFW and temporary TCP connection-limit
operations. Podman Watcher maps those records to runtime `runman`; it does not
pretend Runman is Incus or Podman. Connection-limit requests bind to the VM UUID
and current instance generation.

The adapter does not provide per-process attribution, in-guest service
inspection/remediation, or guest network byte counters. Those Watcher features
remain unavailable for Runman until a separate evidence-backed interface is
implemented.

## Release channels

- Go fork: `main` → `continuous`.
- Rust v2: `rust-v2` → `continuous-rs`.
- Stable Rust releases: `rust-v*` tags.

The Go menu downloads the Rust `install.sh`, migration helper, binary, and
checksums from `continuous-rs`. The Rust branch must publish those assets before
menu item 15 can complete a migration.

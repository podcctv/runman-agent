# Go Agent to Rust v2 migration

Rust v2 is integrated into the fork's `main` source tree as a separate major
runtime and release channel. The root `install.sh` remains the Go installer;
Rust publishes separately to `continuous-rs`. The Go installer offers menu
item 15, which downloads the Rust installer and starts the same `--migrate-go`
flow.

## Supported source and retained settings

The migration supports the standard Go Podman and Incus container backends.
Preflight reads the Go JSON config, takes an SQLite online backup, verifies the
live backend objects, and validates every item before stopping the Go agent.
For Incus, each instance must be `Running` with a valid init PID or `Stopped`;
an `ERROR` state or missing PID aborts preflight before the destructive prompt.
After confirmation it stops Go, takes a final config/database/live-state
snapshot, then gracefully stops the old guests. Incus gets up to 120 seconds
per guest to shut down cleanly; the installer never force-stops a guest after a
timeout.
Before each Incus stop, the helper also checks the reported state and init PID.
If Incus reports `Running` with an invalid PID, migration aborts and keeps the
old guests for manual inspection.

The verified, read-only migration diagnostic is also saved in the root-only
snapshot. If rollback cannot confirm every guest, the installer prints the
command to run it against that snapshot. It reports service/Incus state and
relevant logs without reading the saved passwords or changing host state.

A host with no Go instances can use the same migration. The helper permits an
empty manifest only when both Go instance tables and the complete Podman/Incus
inventory are empty; if containers exist without database records, it refuses
to proceed because their ownership cannot be proven.

It rebuilds clean Rust containers and retains:

- the platform host ID and token, panel user/password hash and listen address;
- each VM UUID, CPU, memory, disk and bandwidth limits;
- Alpine or Debian OS family and whether the guest was running;
- supported TCP/UDP host-to-guest port forwards;
- the supported host IPv6 mode/prefix and RFW API address.

Rust recreates the guest NICs with its own `rmbr0` bridge and isolated veth
pairs; it does not reuse the old Podman/Incus bridge or guest addresses. Before
the Go guests stop, migration inventories all host IPv4 routes and addresses
and selects an unused RFC1918 `/20`. IPv6 SNAT also receives an unused ULA
`/64`. The same plan is kept in the root-only migration snapshot and rechecked
before Rust starts, so a newly occupied subnet aborts safely. After Rust starts,
the installer verifies that every running guest routes through `eth0`, the host
routes each guest address through `rmbr0`, and one migrated guest can reach
the configured DNS servers and IPv4 HTTPS. When IPv6 is enabled, the installer
also checks each guest's IPv6 routes and probes IPv6 HTTPS. A failed network
check triggers the existing Go rollback before the old guests are removed. If
no guest was running, external DNS and egress probes are skipped.

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
instance UUID/run-state inventory, port-forward records, and guest network
route/egress checks pass. It
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

- Go Agent and RFW: `main` → `continuous`.
- Rust v2 artifacts: Rust source changes on `main` → `continuous-rs`.
- Stable Rust releases: `rust-v*` tags.

The Go menu downloads the Rust installer (`install.sh` release asset), migration
helper, read-only diagnostic helper, binary, and checksums from `continuous-rs`.
The Rust release workflow publishes those assets when Rust source changes land
on `main`.

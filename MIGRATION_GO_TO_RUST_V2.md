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
For Incus, each instance may be `Running` with a valid init PID, `Stopped`, or
`ERROR`/missing-PID. An unusable instance is rebuilt as a clean guest after the
operator chooses whether its replacement starts running or stopped. On a normal
migration, the installer installs prerequisites while Go and the old guests
are still intact, then stops Go, takes a final config/database/live-state
snapshot, and checks guest state again. Incus gets up to 120 seconds per healthy
running guest to shut down cleanly; a guest that reports an invalid PID or
becomes `ERROR` during shutdown is marked for clean rebuild and is preserved in
the normal rollback-safe staging path.

If less than 768 MiB is available on the Runman data filesystem, the installer
asks for a second typed confirmation to delete every Go-managed Incus guest
listed in the confirmed snapshot. It first saves VM settings, port forwards, the
Go database/configuration, and generated replacement passwords; then it stops
Go and its guests, deletes the confirmed guests, removes incomplete APT
downloads and unused cached Incus images, and installs host prerequisites before
Rust image staging. A guest still running after the stop phase is not deleted;
new or changed guests discovered after confirmation also abort this cleanup.
If later Rust checks fail, the Go service/configuration can be restored; guests
deleted for disk recovery cannot be restored automatically. Before each Incus
stop, the helper checks the reported state and init PID; an unusable state uses
the rebuild fallback instead of issuing a stop to PID -1.

The verified, read-only migration diagnostic is also saved in the root-only
snapshot. If rollback cannot confirm every guest, the installer prints the
command to run it against that snapshot. It reports service/Incus state and
relevant logs without reading the saved passwords or changing host state.

A host with no Go instances can use the same migration. The helper permits an
empty manifest only when both Go instance tables and the complete Podman/Incus
inventory are empty; if containers exist without database records, it refuses
to proceed because their ownership cannot be proven.

If `vm_configs` contains a core row without a matching selected-backend row,
the helper checks that no live container with that VM UUID exists (across all
Incus projects) and that no port-forward rows reference it. Only these verified
orphan rows are eligible for exclusion. The installer lists their UUID and
saved settings and requires the operator to type `EXCLUDE ORPHAN GO RECORDS`;
the rows are then omitted from the Rust manifest, while the original Go
database remains in the root-only snapshot. A live backend object, a port
forward, a backend-only database row, or a changed orphan set still aborts
migration. After Go stops, the helper rechecks the orphan report against the
pre-confirmation snapshot before it stops or removes any legacy guest.

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
check triggers the existing Go rollback before normally usable old guests are
removed. Incus guests explicitly deleted before staging to recover disk space
are not restored on rollback. If no guest was running, external DNS and egress
probes are skipped.

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
invalid resource settings, unsupported Go config, backend-only records, live
containers without proven Go ownership, unconfirmed orphan rows, occupied
ports, and failed Rust checks abort before normally staged old guests are
purged.

## Rollback boundary

Before normal destructive cleanup, an installer failure stops the partial Rust
service, removes its managed state, restores the Go config/service state, and
restarts recoverable guests that were running before migration. The snapshot
stays under `/var/backups/runman-go-to-rust-v2.*` with mode 0700. If low-space
recovery already deleted Incus guests, Go can return with those containers
absent; the snapshot still preserves their settings and database.

The installer marks migration committed only after the Rust service, panel,
instance UUID/run-state inventory, port-forward records, and guest network
route/egress checks pass. It
then removes normally staged old guest root filesystems. If that cleanup
partially fails, Rust remains active and cleanup is reported as pending; deleted
Go guests cannot be restored automatically. Power loss, hardware faults, and
every package change cannot be guaranteed reversible. Do not describe this
process as 100% rollback guaranteed.

The Go agent is stopped and disabled before Rust starts so both agents never
reconcile the same platform identity concurrently. RFW is not part of guest
migration or cleanup. Before asking for the migration confirmation, the
installer checks an active x86_64 RFW service for repeated recent SIGILL
exits on a host without AVX2. When all evidence matches, it verifies and stages
the published RFW binary. The installer selects `rfw-amd64-legacy`, pinned to
ring 0.17.12 with AVX2 runtime dispatch and P-256 AVX2 paths disabled, when the
host lacks AVX2; AVX2-capable amd64 hosts use the lockfile-selected current
ring build, and arm64 hosts use their lockfile build. All variants are checked
against the release checksum. After confirmation it
replaces only the executable
referenced by the service, then requires the local RFW status API to remain
healthy for 15 seconds. If the existing XDP mode does not start the API and the
candidate has no SIGILL evidence, the installer snapshots a simple local
systemd unit and retries with `--xdp-mode skb`, which is compatible with virtual
NICs and may have lower throughput than native XDP. It records candidate
service/kernel journals in the root-only snapshot. If both attempts fail, it
restores the original executable and unit before stopping Go. Other RFW
installations are left untouched.

The standalone repair command applies only this RFW check and repair, without
installing Rust or changing Go containers:

```sh
bash <(curl -fsSL https://raw.githubusercontent.com/podcctv/runman-agent/main/install-rust-v2.sh) --repair-rfw
```

It creates a root-only backup under `/var/backups/runman-rfw-repair.*` and
prints that path along with the API verification result.

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

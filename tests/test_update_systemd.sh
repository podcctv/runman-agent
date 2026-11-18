#!/usr/bin/env bash
set -euo pipefail

work=$(mktemp -d)
unit="runman-update-test-$$.service"
unit_path="/run/systemd/system/$unit"
guard=$(realpath "$(dirname "$0")/../scripts/runman-update-guard.sh")
cleanup() {
    systemctl stop "$unit" 2>/dev/null || true
    rm -f -- "$unit_path"
    systemctl daemon-reload
    rm -rf -- "$work"
}
trap cleanup EXIT

bin=$work/runman-agent
cat >"$bin.update-previous" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' restored >"$0.ran"
exec sleep infinity
EOF
printf '#!/bin/sh\nexit 1\n' >"$bin"
chmod +x "$bin" "$bin.update-previous"
digest=$(sha256sum -- "$bin")
printf '%s' "${digest%% *}" >"$bin.update-pending"

cat >"$unit_path" <<EOF
[Service]
Type=exec
ExecStartPre=/usr/bin/bash $guard prepare $bin
ExecStart=$bin
ExecStartPost=/usr/bin/bash $guard verify $bin
TimeoutStartSec=110
Restart=always
RestartSec=1
EOF
systemctl daemon-reload
systemctl start --no-block "$unit"
for ((attempt = 0; attempt < 20; attempt++)); do
    if [ -f "$bin.ran" ] && systemctl is-active --quiet "$unit"; then break; fi
    sleep 1
done
systemctl is-active --quiet "$unit"
test "$(cat "$bin.ran")" = restored
test "$(cat "$bin.update-failed")" = "${digest%% *}"
test ! -e "$bin.update-pending"

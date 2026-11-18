#!/usr/bin/env bash
set -euo pipefail

guard=$(dirname "$0")/../scripts/runman-update-guard.sh
workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT
bin=$workspace/runman-agent
printf '#!/bin/sh\n# old binary\n' >"$bin.update-previous"
chmod +x "$bin.update-previous"
printf 'new binary\n' >"$bin"
digest=$(sha256sum "$bin")
printf '%s' "${digest%% *}" >"$bin.update-pending"

bash "$guard" prepare "$bin"
test -f "$bin.update-attempted"
bash "$guard" prepare "$bin"
grep -qx '# old binary' "$bin"
test "$(cat "$bin.update-failed")" = "${digest%% *}"
test ! -e "$bin.update-pending"
bash "$guard" verify "$bin"

printf 'healthy binary\n' >"$bin"
digest=$(sha256sum "$bin")
printf '%s' "${digest%% *}" >"$bin.update-pending"
bash "$guard" prepare "$bin"
touch "$bin.update-ready"
MAINPID=$$ bash "$guard" verify "$bin"
test "$(cat "$bin")" = 'healthy binary'
test ! -e "$bin.update-pending"
test ! -e "$bin.update-attempted"
test ! -e "$bin.update-failed"

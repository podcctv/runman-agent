#!/usr/bin/env bash
set -euo pipefail

phase=$1
bin=$2
pending=$bin.update-pending
attempted=$bin.update-attempted
previous=$bin.update-previous
failed=$bin.update-failed
ready=$bin.update-ready

if [ "$phase" = prepare ]; then
    rm -f -- "$ready"
    [ -f "$pending" ] || exit 0
    target=$(cat -- "$pending")
    [ "${#target}" = 64 ] && [[ $target != *[!0-9a-f]* ]]
    current=$(sha256sum -- "$bin")
    if [ "${current%% *}" != "$target" ]; then
        # Interrupted staging or an explicit installer replacement.
        rm -f -- "$pending" "$attempted"
        exit 0
    fi
    if [ -f "$attempted" ]; then
        [ -x "$previous" ]
        # Record the failed digest before restoring so a restart cannot retry it.
        cp -- "$pending" "$failed".tmp
        mv -f -- "$failed".tmp "$failed"
        mv -f -- "$previous" "$bin"
        rm -f -- "$pending" "$attempted"
        echo "Runman update $target failed readiness checks. Restored previous binary." >&2
    else
        touch -- "$attempted"
    fi
elif [ "$phase" = verify ]; then
    [ -f "$pending" ] || exit 0
    for ((attempt = 0; attempt < 90; attempt++)); do
        if [ -z "${MAINPID:-}" ] || ! kill -0 "$MAINPID" 2>/dev/null; then
            echo "Runman exited before update readiness." >&2
            exit 1
        fi
        if [ -f "$ready" ]; then
            sleep 5
            kill -0 "$MAINPID"
            rm -f -- "$pending" "$attempted" "$ready" "$failed"
            exit 0
        fi
        sleep 1
    done
    echo "Runman update did not become ready in 90 seconds." >&2
    exit 1
else
    exit 2
fi

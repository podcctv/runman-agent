#!/usr/bin/env python3
"""Disable ring's AVX2 dispatch for the legacy RFW artifact only."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path


AVX2_CAPABILITY_ASSIGNMENT = "  OPENSSL_ia32cap_P[2] = extended_features[0];"
AVX2_GUARD = "  if (avx2_available) {"
AVX2_DISABLED_GUARD = "  if (avx2_available && 0) {"
AVX2_MASK = (
    "  /* Runman legacy artifact: disable AVX2 runtime dispatch. */\n"
    "  extended_features[0] &= ~(1u << 5);  /* AVX2 */\n"
)


def patch_ring_source(ring_root: Path) -> bool:
    manifest_path = ring_root / "Cargo.toml"
    cpu_source_path = ring_root / "crypto" / "cpu_intel.c"
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("package", {}).get("name") != "ring":
        raise ValueError("source directory is not the ring crate")
    if manifest["package"].get("version") != "0.17.12":
        raise ValueError("legacy RFW patch only supports ring 0.17.12")

    cpu_source = cpu_source_path.read_text(encoding="utf-8")
    if cpu_source.count(AVX2_MASK) not in (0, 1):
        raise ValueError("ring CPU source contains duplicate Runman AVX2 masks")
    changed = False
    if AVX2_MASK not in cpu_source:
        if cpu_source.count(AVX2_CAPABILITY_ASSIGNMENT) != 1:
            raise ValueError("ring CPU capability assignment changed; refusing to patch")
        if cpu_source.count("extended_features[0] = ebx;") != 1:
            raise ValueError("ring CPUID feature collection changed; refusing to patch")
        cpu_source = cpu_source.replace(
            AVX2_CAPABILITY_ASSIGNMENT,
            AVX2_MASK + AVX2_CAPABILITY_ASSIGNMENT,
            1,
        )
        cpu_source_path.write_text(cpu_source, encoding="utf-8", newline="\n")
        changed = True

    p256_source_path = ring_root / "crypto" / "fipsmodule" / "ec" / "p256-nistz.c"
    p256_source = p256_source_path.read_text(encoding="utf-8")
    disabled_count = p256_source.count(AVX2_DISABLED_GUARD)
    guard_count = p256_source.count(AVX2_GUARD)
    if disabled_count == 2 and guard_count == 0:
        return changed
    if disabled_count != 0 or guard_count != 2:
        raise ValueError("ring P-256 AVX2 dispatch changed; refusing to patch")
    p256_source_path.write_text(
        p256_source.replace(AVX2_GUARD, AVX2_DISABLED_GUARD),
        encoding="utf-8",
        newline="\n",
    )
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ring_root", type=Path)
    args = parser.parse_args()
    try:
        changed = patch_ring_source(args.ring_root.resolve())
    except (OSError, KeyError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"legacy ring CPU patch failed: {error}", file=sys.stderr)
        return 1
    action = (
        "disabled AVX2 runtime dispatch and P-256 AVX2 paths"
        if changed
        else "already has AVX2 runtime dispatch and P-256 paths disabled"
    )
    print(f"ring 0.17.12: {action} for the legacy RFW artifact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

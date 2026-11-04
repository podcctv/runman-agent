#!/usr/bin/env python3
"""Select Rustls' ring provider when building the external RFW workspace.

RFW is checked out from narwhal-cloud/rfw by the release workflow. Reqwest
0.13's `rustls` feature selects aws-lc-rs by default; this downstream patch
uses `rustls-no-provider` and explicitly installs ring before RFW creates an
HTTP client. It deliberately fails closed if the upstream layout changes.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path


REQWEST_RING_DEPENDENCY = (
    'rustls = { version = "0.23", default-features = false, '
    'features = ["ring", "std", "tls12"] }'
)
PROVIDER_INITIALIZATION = """    let _ = rustls::crypto::ring::default_provider().install_default();
"""


def patch_cargo_toml(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    manifest = tomllib.loads(source)
    dependencies = manifest.get("dependencies", {})
    reqwest = dependencies.get("reqwest")
    if not isinstance(reqwest, dict):
        raise ValueError("rfw/Cargo.toml has no table-form reqwest dependency")

    features = reqwest.get("features", [])
    if "rustls" not in features and "rustls-no-provider" not in features:
        raise ValueError("reqwest no longer enables a Rustls TLS feature")

    lines = source.splitlines(keepends=True)
    matches = [
        index
        for index, line in enumerate(lines)
        if re.match(r"^reqwest\s*=\s*\{", line)
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one inline reqwest dependency, found {len(matches)}")

    index = matches[0]
    line = lines[index]
    if "rustls-no-provider" not in line:
        if not re.search(r'features\s*=\s*\[[^\]]*"rustls"', line):
            raise ValueError("reqwest Rustls feature layout changed")
        lines[index] = re.sub(r'"rustls"', '"rustls-no-provider"', line, count=1)

    source = "".join(lines)
    manifest = tomllib.loads(source)
    dependencies = manifest["dependencies"]
    rustls = dependencies.get("rustls")
    if rustls is None:
        marker = "[build-dependencies]"
        if source.count(marker) != 1:
            raise ValueError("could not locate [build-dependencies] in RFW manifest")
        source = source.replace(
            marker,
            f"{REQWEST_RING_DEPENDENCY}\n\n{marker}",
            1,
        )
    elif not (
        isinstance(rustls, dict)
        and rustls.get("default-features") is False
        and {"ring", "std", "tls12"}.issubset(rustls.get("features", []))
    ):
        raise ValueError("an unexpected rustls dependency already exists")

    patched = tomllib.loads(source)
    if "rustls-no-provider" not in patched["dependencies"]["reqwest"].get(
        "features", []
    ):
        raise ValueError("failed to select reqwest's rustls-no-provider feature")
    rustls = patched["dependencies"].get("rustls", {})
    if not {"ring", "std", "tls12"}.issubset(rustls.get("features", [])):
        raise ValueError("failed to enable the ring Rustls provider")

    path.write_text(source, encoding="utf-8", newline="\n")


def patch_main(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    if "rustls::crypto::ring::default_provider().install_default()" in source:
        return

    needle = "async fn main() -> anyhow::Result<()> {\n    let cli = Cli::parse();"
    if source.count(needle) != 1:
        raise ValueError("RFW main entry point changed; cannot safely install provider")
    replacement = (
        "async fn main() -> anyhow::Result<()> {\n"
        + PROVIDER_INITIALIZATION
        + "    let cli = Cli::parse();"
    )
    path.write_text(source.replace(needle, replacement, 1), encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("rfw_root", type=Path)
    root = parser.parse_args().rfw_root.resolve()
    cargo_toml = root / "rfw" / "Cargo.toml"
    main_rs = root / "rfw" / "src" / "main.rs"
    if not cargo_toml.is_file() or not main_rs.is_file():
        parser.error(f"{root} is not an RFW workspace checkout")

    try:
        patch_cargo_toml(cargo_toml)
        patch_main(main_rs)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"RFW ring-provider patch failed: {error}", file=sys.stderr)
        return 1

    print("Selected rustls-ring for RFW TLS; aws-lc-rs is disabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

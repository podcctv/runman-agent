#!/usr/bin/env python3
"""Keep the RFW release binary compatible with legacy persisted rule paths.

The release workflow builds RFW from narwhal-cloud/rfw's dev branch. This
strict, idempotent patch keeps that external source unchanged while ensuring
the binary shipped by this repository can find rules used by existing agents.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValueError(f"expected one {label} marker, found {count}")
    return source.replace(old, new, 1)


def patch_main(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    already_patched = (
        "fn resolve_rules_file(explicit: Option<&str>)" in source
        and "let mut initial_rules = load_rules(&rules_file)?;" in source
        and "rules_path: rules_file," in source
    )
    if already_patched:
        return
    if "fn resolve_rules_file(" in source:
        raise ValueError("RFW rules-path patch is only partially applied")
    if "use anyhow::Context as _;" not in source:
        raise ValueError("RFW main no longer imports anyhow::Context")

    start_marker = "fn load_rules(path: &str) -> RulesState {"
    end_marker = "\n}\n\n// ========== eBPF 同步 =========="
    if source.count(start_marker) != 1:
        raise ValueError("could not uniquely locate RFW load_rules")
    start = source.index(start_marker)
    end = source.find(end_marker, start)
    if end < 0:
        raise ValueError("could not locate RFW load_rules section boundary")
    end += len("\n}")

    rules_loader = '''fn empty_rules_state() -> RulesState {
    RulesState { entries: Vec::new(), next_id: 0, geoip_keys: Vec::new() }
}

fn resolve_rules_file(explicit: Option<&str>) -> anyhow::Result<String> {
    let working_dir = std::env::current_dir().context("resolve RFW working directory")?;
    if let Some(explicit) = explicit {
        let path = std::path::PathBuf::from(explicit);
        let path = if path.is_absolute() { path } else { working_dir.join(path) };
        return Ok(path.to_string_lossy().into_owned());
    }

    let working_dir_rules = working_dir.join("rfw.json");
    if working_dir_rules.is_file() {
        return Ok(working_dir_rules.to_string_lossy().into_owned());
    }

    // Older systemd units used a different WorkingDirectory from the agent
    // directory where the installer and API had persisted rfw.json. When the
    // default file is absent in the working directory, keep those rules live.
    if let Ok(executable) = std::env::current_exe() {
        if let Some(executable_dir) = executable.parent() {
            let executable_rules = executable_dir.join("rfw.json");
            if executable_rules.is_file() {
                warn!(
                    "当前目录没有 rfw.json，改用 RFW 可执行文件目录中的规则文件: {}",
                    executable_rules.display()
                );
                return Ok(executable_rules.to_string_lossy().into_owned());
            }
        }
    }

    // Go and Rust agent installers historically persisted RFW rules beside
    // the Go agent even when the RFW service used another working directory.
    let legacy_agent_rules = std::path::Path::new("/opt/narwhal-agent/rfw.json");
    if legacy_agent_rules.is_file() {
        warn!(
            "默认规则文件不存在，恢复 agent 目录中的旧 RFW 规则: {}",
            legacy_agent_rules.display()
        );
        return Ok(legacy_agent_rules.to_string_lossy().into_owned());
    }

    Ok(working_dir_rules.to_string_lossy().into_owned())
}

fn load_rules(path: &str) -> anyhow::Result<RulesState> {
    let json = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!("规则文件 {} 不存在，RFW 将以空规则表启动", path);
            return Ok(empty_rules_state());
        }
        Err(e) => return Err(e).with_context(|| format!("读取 RFW 规则文件 {path}")),
    };
    let persisted = serde_json::from_str::<PersistedState>(&json)
        .with_context(|| format!("解析 RFW 规则文件 {path}"))?;
    Ok(RulesState {
        next_id: persisted.next_id,
        entries: persisted.entries.into_iter().map(rule_entry_from_persisted).collect(),
        geoip_keys: Vec::new(),
    })
}'''
    source = source[:start] + rules_loader + source[end:]

    old_cli = '''    /// 规则持久化文件路径
    #[clap(long, default_value = "rfw.json")]
    rules_file: String,'''
    new_cli = '''    /// 规则持久化文件路径；默认先读工作目录，缺失时再读可执行文件目录
    #[clap(long)]
    rules_file: Option<String>,'''
    source = replace_once(source, old_cli, new_cli, "CLI rules-file option")

    source = replace_once(
        source,
        "    let mut initial_rules = load_rules(&cli.rules_file);",
        '''    let rules_file = resolve_rules_file(cli.rules_file.as_deref())?;
    info!("RFW 规则文件路径: {}", rules_file);
    let mut initial_rules = load_rules(&rules_file)?;''',
        "startup rules load",
    )
    source = replace_once(
        source,
        '''        info!("已加载 {} 条持久化规则", initial_rules.entries.len());
    }

    let app_state = AppState {''',
        '''        info!("已加载 {} 条持久化规则", initial_rules.entries.len());
    } else {
        warn!("RFW 当前没有持久化规则；协议、端口和 GeoIP 阻断均不会生效");
    }

    let app_state = AppState {''',
        "empty-rules warning",
    )
    source = replace_once(
        source,
        "        rules_path: cli.rules_file.clone(),",
        "        rules_path: rules_file,",
        "persisted rules path",
    )
    path.write_text(source, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("rfw_root", type=Path)
    args = parser.parse_args()
    main_rs = args.rfw_root / "rfw" / "src" / "main.rs"
    if not main_rs.is_file():
        parser.error(f"{args.rfw_root} is not an RFW workspace checkout")
    try:
        patch_main(main_rs)
    except (OSError, ValueError) as error:
        print(f"RFW rules-path patch failed: {error}", file=sys.stderr)
        return 1
    print("RFW will resolve persisted rules across working, executable, and legacy agent paths.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""为注入后的宿主 App 合并 IOSDecryptHub 局域网发现声明。"""

from __future__ import annotations

import os
import plistlib
import sys
import tempfile
from pathlib import Path

SERVICE_TYPE = "_idh-mcp._tcp."
USAGE_DESCRIPTION = "用于在局域网内发现和访问 IOSDecryptHub 调试服务"


def patch_info_plist(path: Path) -> bool:
    raw = path.read_bytes()
    data = plistlib.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Info.plist 顶层必须是 dictionary")

    changed = False
    description = data.get("NSLocalNetworkUsageDescription")
    if not isinstance(description, str) or not description.strip():
        data["NSLocalNetworkUsageDescription"] = USAGE_DESCRIPTION
        changed = True

    services = data.get("NSBonjourServices")
    if services is None:
        services = []
        data["NSBonjourServices"] = services
        changed = True
    if not isinstance(services, list):
        raise ValueError("NSBonjourServices 必须是 array")
    if SERVICE_TYPE not in services:
        services.append(SERVICE_TYPE)
        changed = True

    if not changed:
        return False

    output_format = plistlib.FMT_BINARY if raw.startswith(b"bplist") else plistlib.FMT_XML
    mode = path.stat().st_mode
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        plistlib.dump(data, temporary, fmt=output_format, sort_keys=False)
    os.chmod(temporary_path, mode)
    os.replace(temporary_path, path)
    return True


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"用法: {argv[0]} <Info.plist>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    try:
        changed = patch_info_plist(path)
    except (OSError, ValueError, plistlib.InvalidFileException) as exc:
        print(f"修改 Info.plist 失败: {exc}", file=sys.stderr)
        return 1
    print(f"[*] Info.plist 局域网声明: {'已更新' if changed else '已存在'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))


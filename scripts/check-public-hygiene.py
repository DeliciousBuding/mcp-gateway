#!/usr/bin/env python3
"""check-public-hygiene — mcp-gateway 公开卫生检查（ps1 迁移，契约见 docs/design/ps1-to-python-migration.md）。

行为与 scripts/check-public-hygiene.ps1 一致：
- 枚举 git 跟踪 + 未跟踪文件（排除本脚本），检查敏感模式（vectorcontrol.tech 域名/本机路径/hk* us* 主机名）；
- 命中任一模式即失败（非零退出 + 违规列表）。
"""

import argparse
import os
import re
import subprocess
import sys

PATTERNS = [
    r"vectorcontrol\.tech",
    r"api\.vectorcontrol",
    r"id\.vectorcontrol",
    r"mcp\.vectorcontrol",
    r"agents\.vectorcontrol",
    r"C:\\Users\\Ding",
    r"D:\\Code",
    r"\bhk[0-9]\b",
    r"\bus[0-9]\b",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="mcp-gateway 公开卫生检查")
    parser.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    args = parser.parse_args()

    listing = subprocess.run(
        ["git", "-C", args.root, "ls-files", "--cached", "--others", "--exclude-standard"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=True,
    )
    candidates = [line.strip() for line in listing.stdout.splitlines() if line.strip()]
    candidates = [path for path in candidates if path != "scripts/check-public-hygiene.ps1" and not path.endswith("check-public-hygiene.py")]

    violations = []
    for path in candidates:
        full_path = os.path.join(args.root, path)
        if os.path.isfile(full_path):
            with open(full_path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        else:
            shown = subprocess.run(
                ["git", "-C", args.root, "show", f"HEAD:{path}"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            text = shown.stdout
        for pattern in PATTERNS:
            if re.search(pattern, text):
                violations.append(f"{path}: matched /{pattern}/")

    if violations:
        print(f"Public hygiene check failed:\n" + "\n".join(violations), file=sys.stderr)
        return 1
    print("public hygiene ok")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 —— 顶层兜底，对齐 ps1 $ErrorActionPreference='Stop'
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

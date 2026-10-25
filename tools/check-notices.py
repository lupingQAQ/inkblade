#!/usr/bin/env python3
"""许可证与署名检查（KubeTrail Apache-2.0 移植合规，可执行 CI 门禁）。

检查项：
1. LICENSE 含 Apache License 2.0 全文标识；
2. NOTICE 含 KubeTrail 署名、上游 URL、Apache-2.0 与 trident/kubetrail 路径；
3. ``trident/kubetrail/*.py`` 每个文件含 KubeTrail + Apache-2.0 归属头；
4. ``docs/KUBETRAIL-PORT.md`` 存在且含移植能力清单与许可声明。

用法::

    python tools/check-notices.py            # 0 通过；1 失败并逐条打印
    python tools/check-notices.py --root .
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REQUIRED_NOTICE = (
    "KubeTrail",
    "https://github.com/ekkoo-z/KubeTrail",
    "Apache",
    "trident/kubetrail",
)
REQUIRED_PORT_DOC = ("KubeTrail", "Apache-2.0", "collector", "token", "LPE", "persistence")


def check(root: Path) -> list[str]:
    errors: list[str] = []
    license_path = root / "LICENSE"
    if not license_path.is_file():
        errors.append("缺 LICENSE")
    else:
        text = license_path.read_text(encoding="utf-8", errors="replace")
        if "Apache License" not in text or "Version 2.0" not in text:
            errors.append("LICENSE 不是 Apache-2.0 全文")

    notice = root / "NOTICE"
    if not notice.is_file():
        errors.append("缺 NOTICE")
    else:
        text = notice.read_text(encoding="utf-8", errors="replace")
        for token in REQUIRED_NOTICE:
            if token not in text:
                errors.append(f"NOTICE 缺 {token!r} 署名/说明")

    port_dir = root / "trident" / "kubetrail"
    if not port_dir.is_dir():
        errors.append("缺 trident/kubetrail/ 目录")
    else:
        files = sorted(port_dir.glob("*.py"))
        if not files:
            errors.append("trident/kubetrail/ 无 Python 文件")
        for path in files:
            head = "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[:16])
            if "KubeTrail" not in head or "Apache-2.0" not in head:
                errors.append(f"{path.relative_to(root).as_posix()} 缺 KubeTrail/Apache-2.0 归属头")

    doc = root / "docs" / "KUBETRAIL-PORT.md"
    if not doc.is_file():
        errors.append("缺 docs/KUBETRAIL-PORT.md")
    else:
        text = doc.read_text(encoding="utf-8", errors="replace")
        for token in REQUIRED_PORT_DOC:
            if token not in text:
                errors.append(f"docs/KUBETRAIL-PORT.md 缺 {token!r}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trident license/attribution checker")
    parser.add_argument("--root", default=".", help="仓库根（默认当前目录）")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    errors = check(root)
    if not errors:
        print(f"notices: OK @ {root}")
        return 0
    print(f"notices: {len(errors)} error(s) @ {root}", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

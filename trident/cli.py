"""Trident 命令行入口：python -m trident <子命令>。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core.registry import load_modules
from .core.users import UserStore

DEFAULT_HOME = Path(".")


def _store(home: Path, ws: str):
    from .core.evidence import EvidenceStore

    return EvidenceStore(home, workspace=ws)


def main(argv=None) -> int:
    import sys

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="trident", description="Trident ML-cluster pentest platform (authorized testing)")
    ap.add_argument("--home", default=".", help="工作区根目录（含 evidence/ modules/ users.json）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("module", help="模块管理")
    msub = sp.add_subparsers(dest="mcmd", required=True)
    ml = msub.add_parser("list")
    ml.add_argument("--modules-dir", default=None)

    sub.add_parser("roe", help="查看授权状态").add_argument("--workspace", default="local-lab")

    u = sub.add_parser("user", help="用户管理")
    usub = u.add_subparsers(dest="ucmd", required=True)
    ua = usub.add_parser("add")
    ua.add_argument("name")
    ua.add_argument("password")
    ua.add_argument("role", choices=["admin", "lead", "tester", "auditor"])
    ua.add_argument("--workspaces", default="local-lab")

    sub.add_parser("ui", help="启动本地 Web 控制台").add_argument("--port", type=int, default=8765)

    args = ap.parse_args(argv)
    home = Path(args.home)

    if args.cmd == "module" and args.mcmd == "list":
        mods_dir = Path(args.modules_dir) if args.modules_dir else home / "modules"
        mods = load_modules(mods_dir)
        for key in sorted(mods):
            m = mods[key]
            print(f"{key}\t{m.series}\t{m.min_level}\t{'写' if m.writes else '读'}")
        return 0

    if args.cmd == "roe":
        from .core.roe import roe_status

        print(roe_status(_store(home, args.workspace)))
        return 0

    if args.cmd == "user" and args.ucmd == "add":
        users = UserStore(home / "users.json")
        users.create_user(args.name, args.password, args.role, args.workspaces.split(","))
        print(f"created {args.name}({args.role})")
        return 0

    if args.cmd == "ui":
        from .webui.server import make_server

        users = UserStore(home / "users.json")
        httpd = make_server(home, users, port=args.port)
        print(f"Trident 控制台: http://127.0.0.1:{httpd.port} （Ctrl+C 退出）")
        try:
            import time

            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            httpd.shutdown()
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

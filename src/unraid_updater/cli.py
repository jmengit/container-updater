"""Headless inspection CLI; mutation commands fail closed without a service."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .db import Database
from .evidence import safe_path
from .migration import write_policy_export


def _db(args: argparse.Namespace) -> Database:
    db = Database(args.database)
    db.initialize()
    return db


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="container-updater")
    parser.add_argument("--database", default="sqlite:////data/updater.db")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "candidates", "logs", "audit"):
        sub.add_parser(name)
    for name in ("approve", "execute"):
        command = sub.add_parser(name)
        command.add_argument("candidate_id", type=int)
    migrate = sub.add_parser("export-overrides")
    migrate.add_argument("output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in {"approve", "execute"}:
        print(f"{args.command} is unavailable: no shared service/execution authorization is configured", file=sys.stderr)
        return 2
    db = _db(args)
    if args.command == "export-overrides":
        write_policy_export(db, args.output)
        print(args.output)
        return 0
    if args.command == "status":
        value = db.latest_scan()
    elif args.command == "candidates":
        value = db.list_candidates()
    else:
        value = db.audit_rows()
    print(json.dumps(value, default=str, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

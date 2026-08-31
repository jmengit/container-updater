"""Headless inspection CLI; mutation commands fail closed without a service."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .db import Database
from .migration import write_policy_export


def _db(args: argparse.Namespace) -> Database:
    db = Database(args.database)
    db.initialize()
    return db


def _rows(db: Database, method: str, default: Any) -> Any:
    fn = getattr(db, method, None)
    return fn() if callable(fn) else default


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="container-updater")
    parser.add_argument("--database", default="sqlite:////data/updater.db")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "candidates", "logs", "audit"):
        sub.add_parser(name)
    approve = sub.add_parser("approve")
    approve.add_argument("candidate_id", type=int)
    execute = sub.add_parser("execute")
    execute.add_argument("candidate_id", type=int)
    migrate = sub.add_parser("export-overrides")
    migrate.add_argument("output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in {"approve", "execute"}:
        print(f"{args.command} is unavailable: no shared service/execution authorization is configured", file=sys.stderr)
        return 2
    if args.command == "export-overrides":
        write_policy_export(_db(args), args.output)
        print(args.output)
        return 0
    db = _db(args)
    method = {"status": "latest_scan", "candidates": "active_candidates", "logs": "audit_rows", "audit": "audit_rows"}[args.command]
    print(json.dumps(_rows(db, method, []), default=str, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

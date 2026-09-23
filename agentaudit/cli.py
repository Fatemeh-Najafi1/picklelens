"""agentaudit - detect a betrayed / compromised agent from its execution trace.

    python -m agentaudit audit trace.json [trace2.json ...] [--json]
"""
from __future__ import annotations

import argparse
import json
import sys

from picklelens.rules import Severity

from . import trace as trace_mod
from .detect import audit

_COLORS = {
    "betrayed": "\033[31m", "compromised": "\033[31m", "suspicious": "\033[33m",
    "notable": "\033[36m", "clean": "\033[32m", "reset": "\033[0m",
    "dim": "\033[2m", "bold": "\033[1m",
}


def _c(k: str, on: bool) -> str:
    return _COLORS.get(k, "") if on else ""


def cmd_audit(args: argparse.Namespace) -> int:
    color = sys.stdout.isatty() and not args.no_color
    results = []
    for p in args.trace:
        try:
            results.append(audit(trace_mod.load(p)))
        except Exception as exc:
            print(f"error reading {p}: {exc}", file=sys.stderr)

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            v = r.verdict
            print(f"{_c(v, color)}{v.upper():>11}{_c('reset', color)}  {r.name}")
            for f in r.findings:
                loc = ""
                if f.action_index is not None:
                    loc = f"action@{f.action_index}"
                if f.source_index is not None:
                    loc += (" " if loc else "") + f"src@{f.source_index}"
                print(f"   {_c(v, color)}{f.severity.label:>8}{_c('reset', color)}  "
                      f"{_c('bold', color)}{f.title}{_c('reset', color)}"
                      + (f"  {_c('dim', color)}[{loc}]{_c('reset', color)}" if loc else ""))
                print(f"            {f.detail}")
                if f.attck:
                    print(f"            {_c('dim', color)}ATT&CK {f.attck}{_c('reset', color)}")
                for e in f.evidence:
                    print(f"            {_c('dim', color)}> {e}{_c('reset', color)}")
            if not r.findings:
                print(f"   {_c('dim', color)}no betrayal indicators; all actions trace "
                      f"to trusted input{_c('reset', color)}")

    worst = max((r.severity for r in results), default=Severity.INFO)
    fail_at = Severity[args.fail_on.upper()]
    return 1 if worst >= fail_at else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentaudit",
        description="Detect a betrayed/compromised AI agent from its trace.")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("audit", help="audit one or more agent traces (JSON)")
    a.add_argument("trace", nargs="+")
    a.add_argument("--json", action="store_true")
    a.add_argument("--no-color", action="store_true")
    a.add_argument("--fail-on", default="high",
                   choices=["info", "low", "medium", "high", "critical"])
    a.set_defaults(func=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

"""picklelens - a reachability scanner for pickle-based model files.

Usage:
    python -m picklelens scan <path> [<path> ...] [--json] [--min low|medium|high]
    python -m picklelens scan <dir> --recursive
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .rules import Severity
from .scanner import ScanResult, scan_file

MODEL_SUFFIXES = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt",
                  ".model", ".npy", ".npz", ".safetensors", ".data"}

# ANSI colours, disabled when not writing to a TTY.
_COLORS = {
    "clean": "\033[32m",
    "notable": "\033[36m",
    "suspicious": "\033[33m",
    "malicious": "\033[31m",
    "error": "\033[35m",
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}


def _c(key: str, use_color: bool) -> str:
    return _COLORS[key] if use_color else ""


def _iter_targets(paths: list[str], recursive: bool):
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            it = p.rglob("*") if recursive else p.iterdir()
            for child in sorted(it):
                if child.is_file() and child.suffix.lower() in MODEL_SUFFIXES:
                    yield child
        else:
            yield p


def _print_human(res: ScanResult, use_color: bool, min_sev: Severity) -> None:
    v = res.verdict
    tag = f"{_c(v, use_color)}{v.upper():>10}{_c('reset', use_color)}"
    print(f"{tag}  {res.path}  {_c('dim', use_color)}({res.format}){_c('reset', use_color)}")

    if res.error:
        print(f"            {_c('error', use_color)}{res.error}{_c('reset', use_color)}")
        return

    shown = [f for f in res.findings if f.severity >= min_sev]
    for f in shown:
        arrow = "calls " if f.reachable else "names "
        sev = f"{_c(res.verdict, use_color)}{f.severity.label:>8}{_c('reset', use_color)}"
        print(f"     {sev}  {arrow}{_c('bold', use_color)}{f.qualname}{_c('reset', use_color)}"
              f"  {_c('dim', use_color)}[{f.category}]{_c('reset', use_color)}")
        print(f"               {f.note}")
        print(f"               {_c('dim', use_color)}{f.evidence}"
              f"  (stream {f.stream} @ byte {f.position}, via {f.via}){_c('reset', use_color)}")
    hidden = len(res.findings) - len(shown)
    if hidden > 0:
        print(f"            {_c('dim', use_color)}+{hidden} finding(s) below "
              f"threshold{_c('reset', use_color)}")


def cmd_scan(args: argparse.Namespace) -> int:
    use_color = sys.stdout.isatty() and not args.no_color
    min_sev = Severity[args.min.upper()]

    results = [scan_file(t) for t in _iter_targets(args.path, args.recursive)]

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        if not results:
            print("no model files found")
        for r in results:
            _print_human(r, use_color, min_sev)

    worst = max((r.severity for r in results), default=Severity.INFO)
    n_mal = sum(1 for r in results if r.verdict == "malicious")
    n_sus = sum(1 for r in results if r.verdict == "suspicious")
    if not args.json and results:
        print(f"\n{len(results)} file(s): {n_mal} malicious, {n_sus} suspicious")

    # Exit non-zero when something at or above the fail threshold turned up,
    # so this is usable as a CI gate.
    fail_at = Severity[args.fail_on.upper()]
    return 1 if worst >= fail_at else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="picklelens",
        description="Reachability scanner for pickle-based model files.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan one or more files or directories")
    scan.add_argument("path", nargs="+")
    scan.add_argument("-r", "--recursive", action="store_true",
                      help="descend into subdirectories")
    scan.add_argument("--json", action="store_true", help="emit JSON")
    scan.add_argument("--min", default="low",
                      choices=["info", "low", "medium", "high", "critical"],
                      help="hide findings below this severity in text output")
    scan.add_argument("--fail-on", default="high",
                      choices=["info", "low", "medium", "high", "critical"],
                      help="exit non-zero when a file reaches this severity")
    scan.add_argument("--no-color", action="store_true")
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

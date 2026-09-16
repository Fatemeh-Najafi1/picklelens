"""Head-to-head benchmark: picklelens vs. picklescan on the labelled corpus.

picklescan is the tool Hugging Face runs in its scanning pipeline. It works by
listing the globals a pickle references and matching them against an unsafe
list - a name-based approach. This script runs both tools over the same
samples and reports where each stands.

Out-of-scope samples (malice in installed class code, not the stream) are
excluded from scoring for both tools, since neither can see stream-external
code; they are reported separately.

Run:  python -m tests.benchmark
"""
from __future__ import annotations

import json
from pathlib import Path

from picklelens.scanner import scan_file

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"

try:
    from picklescan.scanner import scan_file_path as _ps_scan
    from picklescan.scanner import SafetyLevel
    HAVE_PICKLESCAN = True
except Exception:  # pragma: no cover
    HAVE_PICKLESCAN = False


def picklelens_verdict(path: Path) -> str:
    """picklelens's own three-way verdict, mapped to block/soft/clean so the
    comparison against picklescan is symmetric: only the hard verdict
    ('malicious' <-> 'dangerous') counts as a block for either tool."""
    v = scan_file(path).verdict
    if v == "malicious":
        return "dangerous"
    if v == "suspicious":
        return "suspicious"
    return "clean"


def picklelens_blocks(path: Path) -> bool:
    return picklelens_verdict(path) == "dangerous"


def picklescan_verdict(path: Path) -> str:
    """Modern picklescan grades each global as Innocuous / Suspicious /
    Dangerous. It counts only *Dangerous* globals as issues, and a file with
    issues_count > 0 is what it reports as infected - the signal a CI gate
    blocks on. 'Suspicious' (any global not on its small safe allowlist) is a
    soft counter that, in a real pipeline flooded with unknown-but-benign
    globals, is triaged by hand or ignored.

    We therefore report picklescan's two distinct verdicts separately:
        'dangerous'  -> would be blocked (issues_count > 0)
        'suspicious' -> flagged softly only (suspicious_count > 0, no issues)
        'clean'      -> innocuous
    """
    res = _ps_scan(str(path))
    if getattr(res, "issues_count", 0) > 0:
        return "dangerous"
    if getattr(res, "suspicious_count", 0) > 0:
        return "suspicious"
    return "clean"


def picklescan_blocks(path: Path) -> bool:
    """The honest 'would this be blocked' signal: only Dangerous counts."""
    return picklescan_verdict(path) == "dangerous"


def run() -> dict:
    manifest = json.loads((SAMPLES / "manifest.json").read_text())
    in_scope = [e for e in manifest if e["in_scope"]]
    out_scope = [e for e in manifest if not e["in_scope"]]

    # Blocking verdict: what each tool would actually stop in a CI gate.
    # Symmetric: for BOTH tools, only the hard verdict counts as a block; the
    # soft 'suspicious' bucket counts as a miss for both.
    tools = {"picklelens": picklelens_blocks}
    if HAVE_PICKLESCAN:
        tools["picklescan"] = picklescan_blocks

    w = 14
    print(f"{'sample':28} {'family':20} {'truth':5}", end="")
    for name in tools:
        print(f" {name:>{w}}", end="")
    if HAVE_PICKLESCAN:
        print(f" {'ps-raw':>11}", end="")
    print()
    print("-" * (28 + 20 + 6 + w * len(tools) + 12))

    stats = {name: dict(tp=0, tn=0, fp=0, fn=0) for name in tools}
    for e in in_scope:
        truth = e["malicious"]
        print(f"{e['name']:28} {e['family']:20} {'MAL' if truth else 'safe':5}", end="")
        for name, fn in tools.items():
            flagged = fn(SAMPLES / e["name"])
            s = stats[name]
            if truth and flagged: s["tp"] += 1; cell = "block"
            elif truth and not flagged: s["fn"] += 1; cell = "MISS"
            elif not truth and flagged: s["fp"] += 1; cell = "FALSE+"
            else: s["tn"] += 1; cell = "pass"
            print(f" {cell:>{w}}", end="")
        print(f"   pl={picklelens_verdict(SAMPLES / e['name']):>10}", end="")
        if HAVE_PICKLESCAN:
            print(f" ps={picklescan_verdict(SAMPLES / e['name']):>10}", end="")
        print()

    print("\nBlocking scores (would a CI gate stop it? in-scope samples only):")
    for name, s in stats.items():
        total = sum(s.values())
        mal = s["tp"] + s["fn"]
        recall = s["tp"] / mal if mal else 0.0
        print(f"  {name:12} blocks {s['tp']}/{mal} malicious "
              f"(recall {recall:.0%}), {s['fp']} false alarms")

    if HAVE_PICKLESCAN:
        pl, ps = stats["picklelens"], stats["picklescan"]
        gained = ps["fn"] - pl["fn"]
        misses = [e["name"] for e in in_scope
                  if e["malicious"] and not picklescan_blocks(SAMPLES / e["name"])
                  and picklelens_blocks(SAMPLES / e["name"])]
        if gained > 0:
            print(f"\npicklelens blocks {gained} malicious payload(s) that "
                  f"picklescan lets through (marks only 'suspicious', not blocked):")
            for m in misses:
                print(f"    - {m}")
        print("\nNote: picklescan marks unknown globals 'suspicious' (soft). It is"
              "\nnot a naive blocklist. picklelens's edge is precision - it grades"
              "\nby what the pickle actually *invokes*, resolving reflection and"
              "\nalias chains to the real callable, so the blocking verdict"
              "\ncorresponds to reachable code execution rather than name presence.")

    if out_scope:
        print("\nOut-of-scope (neither tool can see stream-external code):")
        for e in out_scope:
            print(f"  {e['name']} [{e['family']}] - excluded from scoring")

    return stats


if __name__ == "__main__":
    run()

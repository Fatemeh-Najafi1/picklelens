"""Four-way benchmark: picklelens vs picklescan vs ModelScan vs Fickling.

Extends the picklescan head-to-head to the other public pickle/model scanners:
  - picklescan  (Hugging Face's scanner; name-based allow/deny lists)
  - ModelScan   (Protect AI; multi-format, unsafe-operator lists)
  - Fickling    (Trail of Bits; opcode decompiler + severity grading)

Each tool gets a "blocks" signal, defined *generously* for the competitors so a
picklelens win is honest, never stacked:
  - picklelens: verdict == malicious (its hard verdict)
  - picklescan: issues_count > 0 (its "dangerous"/infected signal)
  - ModelScan:  any issue reported
  - Fickling:   severity >= SUSPICIOUS (giving it credit for soft flags too)

A tool that errors on a valid file counts as "did not block" (robustness is part
of the comparison) and the error is tallied separately. Recall is over malicious
in-scope samples; FPR over benign ones.

Run:  python -m tests.benchmark_scanners
"""
from __future__ import annotations

import json
from pathlib import Path

from picklelens.scanner import scan_file

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


def picklelens_blocks(path: Path) -> tuple[bool, bool]:
    """(blocked, errored)."""
    try:
        return scan_file(path).verdict == "malicious", False
    except Exception:
        return False, True


def picklescan_blocks(path: Path) -> tuple[bool, bool]:
    try:
        from picklescan.scanner import scan_file_path
        return scan_file_path(str(path)).issues_count > 0, False
    except Exception:
        return False, True


def modelscan_blocks(path: Path) -> tuple[bool, bool]:
    try:
        from modelscan.modelscan import ModelScan
        res = ModelScan().scan(str(path))
        return len(res.get("issues", [])) > 0, False
    except Exception:
        return False, True


def fickling_blocks(path: Path) -> tuple[bool, bool]:
    try:
        from fickling.analysis import check_safety, Severity
        import fickling.fickle as ff
        with open(path, "rb") as f:
            pickled = ff.Pickled.load(f.read())
        sev = check_safety(pickled).severity
        order = list(Severity)
        return order.index(sev) >= order.index(Severity.SUSPICIOUS), False
    except Exception:
        return False, True


def modelhawk_blocks(path: Path) -> tuple[bool, bool]:
    """ModelHawk (github.com/Pyhroff/ModelHawk) - the closest stdlib sibling.
    Importable if its modelhawk.py is on sys.path or MODELHAWK_DIR is set."""
    try:
        import os
        import sys
        d = os.environ.get("MODELHAWK_DIR")
        if d and d not in sys.path:
            sys.path.insert(0, d)
        from modelhawk import scan_file, SEVERITY_ORDER
        v = scan_file(str(path)).verdict
        return SEVERITY_ORDER.get(v, 0) >= 3, False  # >= MEDIUM (generous)
    except Exception:
        return False, True


TOOLS = {
    "picklelens": picklelens_blocks,
    "picklescan": picklescan_blocks,
    "modelscan": modelscan_blocks,
    "fickling": fickling_blocks,
    "modelhawk": modelhawk_blocks,
}


def run() -> dict:
    manifest = json.loads((SAMPLES / "manifest.json").read_text())
    in_scope = [e for e in manifest if e["in_scope"]]

    # Drop tools that aren't installed (they error on a known-malicious probe).
    probe = SAMPLES / "mal_direct.pkl"
    tools = {}
    for name, fn in TOOLS.items():
        blocked, errored = fn(probe)
        if errored and not blocked:
            print(f"(skipping {name}: not installed)")
        else:
            tools[name] = fn

    stats = {t: dict(tp=0, fn=0, tn=0, fp=0, err=0) for t in tools}
    names = list(tools)
    print(f"{'sample':30} {'truth':5} " + " ".join(f"{n:>11}" for n in names))
    print("-" * (36 + 12 * len(names)))
    for e in in_scope:
        mal = e["malicious"]
        row = f"{e['name']:30} {'MAL' if mal else 'safe':5} "
        for name, fn in tools.items():
            blocked, errored = fn(SAMPLES / e["name"])
            s = stats[name]
            if errored:
                s["err"] += 1
            if mal and blocked:
                s["tp"] += 1; cell = "block"
            elif mal and not blocked:
                s["fn"] += 1; cell = "MISS" + ("(err)" if errored else "")
            elif not mal and blocked:
                s["fp"] += 1; cell = "FALSE+"
            else:
                s["tn"] += 1; cell = "pass"
            row += f" {cell:>11}"
        print(row)

    print("\nBlocking recall / false-positive rate (in-scope samples):")
    n_mal = sum(1 for e in in_scope if e["malicious"])
    n_ben = sum(1 for e in in_scope if not e["malicious"])
    for name, s in stats.items():
        recall = s["tp"] / n_mal if n_mal else 0.0
        fpr = s["fp"] / n_ben if n_ben else 0.0
        err = f", {s['err']} parse error(s)" if s["err"] else ""
        print(f"  {name:12} recall {s['tp']}/{n_mal} ({recall:.0%}), "
              f"FPR {s['fp']}/{n_ben} ({fpr:.0%}){err}")
    return stats


if __name__ == "__main__":
    run()

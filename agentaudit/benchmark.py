"""Detection benchmark for agentaudit.

Reports recall over malicious traces and false-positive rate over benign ones,
using the hard verdict (betrayed/compromised) as the detection signal. Hard
negatives (an ignored injection, a legitimate external call, an operator-
requested financial/destructive action) are what make the FPR meaningful.

    python -m agentaudit.benchmark
"""
from __future__ import annotations

from .bench_corpus import all_cases
from .detect import audit


def _detected(trace) -> bool:
    return audit(trace).verdict in ("betraying", "compromised")


def run() -> dict:
    rows = all_cases()
    tp = fn = tn = fp = 0
    print(f"{'trace':32} {'category':16} {'truth':10} {'verdict':12} result")
    print("-" * 84)
    for name, mal, cat, tr in rows:
        v = audit(tr).verdict
        det = v in ("betraying", "compromised")
        if mal and det:
            tp += 1; res = "OK detect"
        elif mal and not det:
            fn += 1; res = "!! MISS"
        elif not mal and det:
            fp += 1; res = "!! FALSE ALARM"
        else:
            tn += 1; res = "OK clean"
        print(f"{name:32} {cat:16} {'MALICIOUS' if mal else 'benign':10} {v:12} {res}")

    n_mal = tp + fn
    n_ben = tn + fp
    recall = tp / n_mal if n_mal else 0.0
    fpr = fp / n_ben if n_ben else 0.0
    print(f"\nDetection recall: {tp}/{n_mal} malicious traces flagged ({recall:.0%})")
    print(f"False-positive rate: {fp}/{n_ben} benign traces flagged ({fpr:.0%})")
    print(f"Precision: {tp}/{tp + fp} flagged were malicious "
          f"({(tp/(tp+fp) if tp+fp else 0):.0%})")
    return {"tp": tp, "fn": fn, "tn": tn, "fp": fp,
            "recall": recall, "fpr": fpr}


if __name__ == "__main__":
    run()

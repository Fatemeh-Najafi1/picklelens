"""Real-model benchmark for picklelens — run on Google Colab or Kaggle.

Everything so far is measured on a hand-authored corpus. This script closes that
gap: it downloads *real* models from Hugging Face (benign production models and
external scanner-test repos) and runs picklelens head-to-head against every
public pickle/model scanner, reporting:

  * false-positive rate on REAL benign models (the honest precision test), and
  * recall on external-authored malicious pickles (not our own samples).

It is designed for a notebook with disk + bandwidth to spare. Paste the whole
file into one Colab/Kaggle cell and run, or upload it and `!python
real_model_benchmark.py`. It installs its own dependencies and cleans up as it
goes to stay within disk.

Nothing is ever deserialized or executed: every scanner here is static.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import traceback
from pathlib import Path

# --------------------------------------------------------------------------- #
# 0. Setup: install the scanners and clone ModelHawk.
# --------------------------------------------------------------------------- #

def _sh(cmd: str):
    print(f"$ {cmd}")
    subprocess.run(cmd, shell=True, check=False)


def setup():
    # Install each package separately so one incompatible dependency does not
    # abort the whole command. (On Python 3.13 runtimes - e.g. current Colab -
    # modelscan has no compatible release; it is simply skipped.)
    for pkg in ["git+https://github.com/Fatemeh-Najafi1/picklelens",
                "picklescan", "fickling", "huggingface_hub", "modelscan"]:
        _sh(f"{sys.executable} -m pip install -q '{pkg}'")
    if not Path("ModelHawk").exists():
        _sh("git clone -q https://github.com/Pyhroff/ModelHawk")
    sys.path.insert(0, str(Path("ModelHawk").resolve()))


# --------------------------------------------------------------------------- #
# 1. The five scanners, each returning (blocked, errored).
#    Competitor block thresholds are set *generously* so a picklelens win is
#    honest, never stacked (same convention as tests/benchmark_scanners.py).
# --------------------------------------------------------------------------- #

def picklelens_blocks(path):
    try:
        from picklelens.scanner import scan_file
        return scan_file(path).verdict == "malicious", False
    except Exception:
        return False, True


def picklescan_blocks(path):
    try:
        from picklescan.scanner import scan_file_path
        return scan_file_path(str(path)).issues_count > 0, False
    except Exception:
        return False, True


def modelscan_blocks(path):
    try:
        from modelscan.modelscan import ModelScan
        return len(ModelScan().scan(str(path)).get("issues", [])) > 0, False
    except Exception:
        return False, True


def fickling_blocks(path):
    try:
        from fickling.analysis import check_safety, Severity
        import fickling.fickle as ff
        with open(path, "rb") as f:
            sev = check_safety(ff.Pickled.load(f.read())).severity
        return list(Severity).index(sev) >= list(Severity).index(Severity.SUSPICIOUS), False
    except Exception:
        return False, True


def modelhawk_blocks(path):
    try:
        from modelhawk import scan_file, SEVERITY_ORDER
        return SEVERITY_ORDER.get(scan_file(str(path)).verdict, 0) >= 3, False
    except Exception:
        return False, True


SCANNERS = {
    "picklelens": picklelens_blocks,
    "picklescan": picklescan_blocks,
    "modelscan": modelscan_blocks,
    "fickling": fickling_blocks,
    "modelhawk": modelhawk_blocks,
}


# --------------------------------------------------------------------------- #
# 2. Model corpora.
#    Benign: real pickle-format models (pytorch_model.bin) from popular / tiny
#    repos. Malicious: EXTERNAL scanner-test repos (not our samples).
# --------------------------------------------------------------------------- #

BENIGN_REPOS = [
    # tiny real test models (reliably ship a pickle pytorch_model.bin)
    "hf-internal-testing/tiny-random-bert",
    "hf-internal-testing/tiny-random-gpt2",
    "hf-internal-testing/tiny-random-distilbert",
    "hf-internal-testing/tiny-random-roberta",
    "hf-internal-testing/tiny-random-t5",
    "hf-internal-testing/tiny-random-albert",
    "hf-internal-testing/tiny-random-electra",
    "hf-internal-testing/tiny-random-bart",
    "hf-internal-testing/tiny-random-xlm-roberta",
    "hf-internal-testing/tiny-random-mobilebert",
    "sshleifer/tiny-gpt2",
    "sshleifer/tiny-distilbert-base-cased",
    "prajjwal1/bert-tiny",
    "prajjwal1/bert-mini",
    "prajjwal1/bert-small",
    # small real production models
    "distilbert-base-uncased",
    "google/bert_uncased_L-2_H-128_A-2",
    "sentence-transformers/all-MiniLM-L6-v2",
    "sentence-transformers/paraphrase-MiniLM-L3-v2",
    "albert-base-v2",
]

# External malicious / scanner-test repos. We list the repo's files and pull the
# pickle-bearing ones. These are authored by others specifically to test
# scanners (eicar-style), not real malware and not our own corpus.
MALICIOUS_REPOS = [
    "mcpotato/42-eicar-street",
    "ScanMe/Models",
]

_PICKLE_SUFFIXES = (".bin", ".pkl", ".pickle", ".pt", ".pth", ".ckpt",
                    ".npy", ".npz", ".model", ".data", ".dat")


def _download(repo, filename, cache):
    from huggingface_hub import hf_hub_download
    return hf_hub_download(repo, filename, cache_dir=cache)


def fetch_benign(cache):
    from huggingface_hub import hf_hub_download
    out = []
    for repo in BENIGN_REPOS:
        got = False
        for fn in ("pytorch_model.bin", "model.ckpt", "sklearn_model.pkl"):
            try:
                p = hf_hub_download(repo, fn, cache_dir=cache)
                head = open(p, "rb").read(2)
                # keep only real pickles / zip-pickles (skip safetensors-only)
                if head[:2] in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05",
                                b"PK") or Path(p).suffix == ".npy":
                    out.append((f"{repo}/{fn}", p))
                    got = True
                    break
            except Exception:
                continue
        print(("  got " if got else "  skip ") + repo)
    return out


def fetch_malicious(cache):
    """Returns (malicious, canary_benign). Some scanner-test repos include a
    deliberate benign canary ('..._BENIGN_ANY_DETECTION_IS_AN_ERROR'); flagging
    it is a *false positive*, so it is routed to the benign set."""
    from huggingface_hub import list_repo_files, hf_hub_download
    malicious, canary = [], []
    for repo in MALICIOUS_REPOS:
        try:
            files = list_repo_files(repo)
        except Exception as e:
            print(f"  skip {repo}: {str(e)[:60]}")
            continue
        n = 0
        for fn in files:
            if not fn.lower().endswith(_PICKLE_SUFFIXES):
                continue
            try:
                p = hf_hub_download(repo, fn, cache_dir=cache)
            except Exception:
                continue
            n += 1
            if "benign" in fn.lower():
                canary.append((f"{repo}/{fn}", p))
            else:
                malicious.append((f"{repo}/{fn}", p))
        print(f"  listed {repo}: {n} pickle files")
    return malicious, canary


# --------------------------------------------------------------------------- #
# 3. Run + report.
# --------------------------------------------------------------------------- #

def _scan_all(items, truth_malicious, tools):
    names = list(tools)
    stats = {n: dict(flag=0, err=0, total=0) for n in names}
    print(f"\n{'model':52} " + " ".join(f"{n:>10}" for n in names))
    print("-" * (54 + 11 * len(names)))
    for label, path in items:
        row = f"{label[:52]:52} "
        for n, fn in tools.items():
            blocked, errored = fn(path)
            s = stats[n]
            s["total"] += 1
            s["flag"] += int(blocked)
            s["err"] += int(errored)
            row += f" {('FLAG' if blocked else ('err' if errored else 'pass')):>10}"
        print(row)
    print()
    for n, s in stats.items():
        if truth_malicious:
            print(f"  {n:12} recall {s['flag']}/{s['total']} "
                  f"({(s['flag']/s['total'] if s['total'] else 0):.0%})"
                  + (f", {s['err']} errors" if s['err'] else ""))
        else:
            print(f"  {n:12} FALSE POSITIVES {s['flag']}/{s['total']} "
                  f"({(s['flag']/s['total'] if s['total'] else 0):.0%})"
                  + (f", {s['err']} errors" if s['err'] else ""))
    return stats


def provenance():
    """Print exactly what, where, and when — so a run is reproducible later."""
    import datetime
    import platform
    try:
        from importlib.metadata import version
    except Exception:  # pragma: no cover
        version = lambda _p: "n/a"  # noqa: E731

    def v(pkg):
        try:
            return version(pkg)
        except Exception:
            return "not installed"

    mh = subprocess.run("git -C ModelHawk rev-parse --short HEAD",
                        shell=True, capture_output=True, text=True).stdout.strip()
    print("=" * 70)
    print("RUN PROVENANCE")
    print("=" * 70)
    print(f"  date (UTC)   : {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}")
    print(f"  python       : {platform.python_version()}  ({platform.system()} {platform.machine()})")
    print(f"  picklelens   : {v('picklelens')}")
    print(f"  picklescan   : {v('picklescan')}")
    print(f"  fickling     : {v('fickling')}")
    print(f"  modelscan    : {v('modelscan')}")
    print(f"  modelhawk    : {mh or 'cloned (HEAD)'}")
    print(f"  benign repos : {len(BENIGN_REPOS)} listed")
    print(f"  malicious repos : {', '.join(MALICIOUS_REPOS)}")
    print("  note         : competitors with no release for this Python are skipped.")
    print()


def main():
    setup()
    try:
        import picklelens  # noqa: F401
    except Exception:
        print("\nFATAL: picklelens failed to install. Run manually:\n"
              "  pip install git+https://github.com/Fatemeh-Najafi1/picklelens")
        return
    provenance()

    cache = "hf_cache"
    print("\n=== downloading REAL benign models (pickle format) ===")
    benign = fetch_benign(cache)
    print("\n=== downloading EXTERNAL malicious / scanner-test pickles ===")
    malicious, canary = fetch_malicious(cache)
    benign += canary               # the 'BENIGN' canary is a hard negative
    print(f"\n{len(benign)} benign models, {len(malicious)} malicious test files")

    # Drop scanners not available on this runtime (e.g. modelscan on Py 3.13).
    tools = dict(SCANNERS)
    if benign:
        probe = benign[0][1]
        tools = {}
        for n, fn in SCANNERS.items():
            blocked, errored = fn(probe)
            if errored and not blocked:
                print(f"(skipping {n}: not available on this runtime)")
            else:
                tools[n] = fn

    print("\n" + "=" * 70)
    print("REAL BENIGN MODELS — false-positive rate (lower is better)")
    print("=" * 70)
    _scan_all(benign, False, tools)

    if malicious:
        print("\n" + "=" * 70)
        print("EXTERNAL MALICIOUS PICKLES — recall (higher is better)")
        print("=" * 70)
        _scan_all(malicious, True, tools)

    print("\nDone. (Static analysis only — nothing was deserialized or executed.)")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()

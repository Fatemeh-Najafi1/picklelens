"""Scale precision study — scan many real Hugging Face models (Colab / Kaggle).

The curated real-model benchmark (real_model_benchmark.py) shows picklelens at
0% FPR on 20 models. This script makes the precision claim robust at *scale*: it
walks the most-downloaded models on the Hub that ship a pickle-format file,
scans each with picklelens and the other scanners, and reports the aggregate
**flag rate on popular (presumed-benign) models** — where a flag is a false
positive unless the model is genuinely malicious.

Honest framing:
- This is a PRECISION study. Popular models are treated as benign ground truth
  (reasonable for high-download repos); every flag is listed so you can inspect
  whether it is a false positive or a real malicious-in-the-wild find.
- It is NOT a recall study: real malicious models on the Hub are rare and removed
  quickly, so scanning popular repos won't reliably surface them.
- Most modern repos are safetensors-only (no code-execution primitive); those
  are skipped so we actually exercise the pickle path.

Disk-safe: each file is downloaded, scanned, then deleted before the next, so
peak disk stays ~one model. Paste into a Colab/Kaggle cell, or:
    !python hub_scan.py --n 300 --max-mb 300

Nothing is deserialized or executed — every scanner is static.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

_PICKLE_SUFFIXES = (".bin", ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".model")
_PICKLE_HEADS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05", b"PK")


def _sh(cmd):
    print(f"$ {cmd}")
    subprocess.run(cmd, shell=True, check=False)


def setup():
    for pkg in ["git+https://github.com/Fatemeh-Najafi1/picklelens",
                "picklescan", "fickling", "huggingface_hub", "modelscan"]:
        _sh(f"{sys.executable} -m pip install -q '{pkg}'")
    if not Path("ModelHawk").exists():
        _sh("git clone -q https://github.com/Pyhroff/ModelHawk")
    sys.path.insert(0, str(Path("ModelHawk").resolve()))


# --- scanners (generous competitor thresholds; a flag counts for any tool) --- #

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


def provenance(args):
    import datetime
    import platform
    try:
        from importlib.metadata import version
    except Exception:
        version = lambda _p: "n/a"  # noqa: E731

    def v(p):
        try:
            return version(p)
        except Exception:
            return "not installed"
    mh = subprocess.run("git -C ModelHawk rev-parse --short HEAD",
                        shell=True, capture_output=True, text=True).stdout.strip()
    print("=" * 70)
    print("RUN PROVENANCE — Hub scale precision study")
    print("=" * 70)
    print(f"  date (UTC) : {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}")
    print(f"  python     : {platform.python_version()} ({platform.system()} {platform.machine()})")
    print(f"  picklelens : {v('picklelens')}   picklescan: {v('picklescan')}   "
          f"fickling: {v('fickling')}   modelscan: {v('modelscan')}   modelhawk: {mh or 'HEAD'}")
    print(f"  target     : {args.n} pickle-format models, sorted by downloads, "
          f"each pickle file < {args.max_mb} MB")
    print()


def _pick_pickle_file(info, max_bytes):
    """Smallest pickle-format sibling under the size cap, if any."""
    cands = []
    for s in getattr(info, "siblings", []) or []:
        name = s.rfilename
        size = getattr(s, "size", None)
        if name.lower().endswith(_PICKLE_SUFFIXES) and size and size < max_bytes:
            # de-prioritise optimizer/training shards; prefer the model weights
            rank = 0 if "pytorch_model" in name else 1
            cands.append((rank, size, name))
    cands.sort()
    return cands[0][2] if cands else None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="hub_scan")
    ap.add_argument("--n", type=int, default=300, help="models to scan")
    ap.add_argument("--max-mb", type=int, default=300, help="skip pickle files larger than this")
    ap.add_argument("--examine", type=int, default=4000, help="max repos to examine to find --n with a pickle")
    args = ap.parse_args(argv)

    setup()
    try:
        import picklelens  # noqa: F401
    except Exception:
        print("FATAL: picklelens failed to install.")
        return
    provenance(args)

    from huggingface_hub import list_models, hf_hub_download, HfApi
    api = HfApi()
    max_bytes = args.max_mb * 1024 * 1024

    # Probe which scanners are available on this runtime (first real file).
    tools = None
    stats = {n: dict(flag=0, err=0, total=0) for n in SCANNERS}
    flagged = {n: [] for n in SCANNERS}
    scanned = 0
    examined = 0
    tmp = Path("hub_tmp")

    print("Scanning popular Hub models that ship a pickle file...\n")
    for m in list_models(sort="downloads", direction=-1, limit=args.examine):
        if scanned >= args.n:
            break
        examined += 1
        try:
            info = api.model_info(m.id, files_metadata=True)
        except Exception:
            continue
        fn = _pick_pickle_file(info, max_bytes)
        if not fn:
            continue  # safetensors-only or too big
        shutil.rmtree(tmp, ignore_errors=True)
        try:
            p = hf_hub_download(m.id, fn, local_dir=str(tmp))
        except Exception:
            continue
        head = b""
        try:
            with open(p, "rb") as fh:
                head = fh.read(2)
        except Exception:
            pass
        if head[:2] not in _PICKLE_HEADS and not fn.lower().endswith((".pt", ".pth", ".ckpt")):
            shutil.rmtree(tmp, ignore_errors=True)
            continue

        if tools is None:  # first real file: drop scanners that error on it
            tools = {}
            for n, f in SCANNERS.items():
                blocked, errored = f(p)
                if errored and not blocked:
                    print(f"(skipping {n}: not available on this runtime)")
                else:
                    tools[n] = f
            print()

        scanned += 1
        verdicts = []
        for n, f in tools.items():
            blocked, errored = f(p)
            s = stats[n]
            s["total"] += 1
            s["err"] += int(errored)
            if blocked:
                s["flag"] += 1
                flagged[n].append(f"{m.id}/{fn}")
            verdicts.append(f"{n}={'FLAG' if blocked else 'pass'}")
        if scanned % 20 == 0 or any("FLAG" in v for v in verdicts):
            print(f"[{scanned}/{args.n}] {m.id}/{fn}  " + " ".join(verdicts))
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 70)
    print(f"RESULTS — {scanned} popular pickle-format models scanned "
          f"({examined} repos examined)")
    print("=" * 70)
    print("Flag rate on popular (presumed-benign) models — lower is better:\n")
    for n in (tools or {}):
        s = stats[n]
        print(f"  {n:12} flagged {s['flag']}/{s['total']} "
              f"({(s['flag']/s['total'] if s['total'] else 0):.1%})"
              + (f", {s['err']} parse errors" if s['err'] else ""))
    for n in (tools or {}):
        if flagged[n]:
            print(f"\n  {n} flagged (inspect — false positive unless genuinely malicious):")
            for r in flagged[n][:50]:
                print(f"    - {r}")
    print("\nDone. (Static analysis only — nothing was deserialized or executed.)")


if __name__ == "__main__":
    main()

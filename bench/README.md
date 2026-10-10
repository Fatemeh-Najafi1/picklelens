# Real-model benchmark (Colab / Kaggle)

`real_model_benchmark.py` runs picklelens head-to-head against every public
pickle/model scanner on **real models downloaded from Hugging Face**, not our
hand-authored corpus. It reports:

- **false-positive rate on real benign models** (the honest precision test), and
- **recall on external-authored malicious pickles** (scanner-test repos, not our
  samples).

It needs disk + bandwidth, so run it on **Google Colab** or **Kaggle**, not a
laptop. Nothing is deserialized or executed — every scanner is static.

## Google Colab

1. Open <https://colab.research.google.com> → New notebook.
2. In one cell, fetch and run the script:
   ```python
   !wget -q https://raw.githubusercontent.com/Fatemeh-Najafi1/picklelens/main/bench/real_model_benchmark.py
   !python real_model_benchmark.py
   ```
   (Or paste the file's contents into a cell and run.)

## Kaggle

1. <https://www.kaggle.com/code> → New Notebook → enable **Internet** in the
   right-hand settings panel.
2. Same two lines as above in a cell.

## What you get

```
REAL BENIGN MODELS — false-positive rate (lower is better)
  picklelens   FALSE POSITIVES 0/N (0%)
  picklescan   FALSE POSITIVES x/N (..%)
  modelscan    ...
  fickling     ...
  modelhawk    ...

EXTERNAL MALICIOUS PICKLES — recall (higher is better)
  picklelens   recall m/M (..%)
  ...
```

The honest headline to watch for: whether picklelens keeps **0 false positives
on real production models** while competitors false-flag some — that is the
real-world precision claim our synthetic corpus can only hint at.

Edit `BENIGN_REPOS` / `MALICIOUS_REPOS` in the script to widen the corpus.
Downloads that 404 (models that are safetensors-only now) are skipped
automatically.

## Run records

Each real run is recorded under `bench/results/` with its date, environment,
tool versions, exact model list, and results — so numbers stay trackable and
reproducible. See [`results/2026-10-10-colab.md`](results/2026-10-10-colab.md).
The harness also prints a provenance header (date, Python version, installed
scanner versions, corpus) at the start of every run.

## Scale precision study (`hub_scan.py`)

`hub_scan.py` walks the most-downloaded Hub models that ship a pickle file,
scans each, and reports the aggregate **flag rate on popular (presumed-benign)
models** — the precision claim at scale. It downloads, scans, and deletes each
model in turn, so peak disk stays ~one model (safe for N in the hundreds).

Colab / Kaggle (one cell; Kaggle needs Internet on):
```python
!wget -qO hub_scan.py "https://raw.githubusercontent.com/Fatemeh-Najafi1/picklelens/main/bench/hub_scan.py"
!python hub_scan.py --n 300 --max-mb 300
```

`--n` models to scan, `--max-mb` skips pickle files larger than this (keeps the
run bounded). Every flag is listed so it can be inspected — on popular models a
flag is a false positive unless the model is genuinely malicious. This is a
*precision* study, not recall (real malicious models on the Hub are rare and
removed quickly). Save the printed provenance + results as a new
`results/<date>-hub-scan.md`.

**First run recorded:** [`results/2026-10-10-hub-scan.md`](results/2026-10-10-hub-scan.md)
— 100 popular real models (761 repos examined): **picklelens 0/100 false
positives**, picklescan 0/100, ModelHawk 30/100 (mostly routine
`training_args.bin`).

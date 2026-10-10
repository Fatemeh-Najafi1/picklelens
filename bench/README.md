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

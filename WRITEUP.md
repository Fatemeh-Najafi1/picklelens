# picklelens — project writeup

*A reachability-based scanner for malicious ML model files, plus an experimental
detector for hijacked AI agents. Built as a security engineering project; every
claim below is backed by a reproducible benchmark in this repo.*

---

## The problem

Machine-learning models are shipped as files, and most of those files are Python
**pickles** — the format behind `torch.load`, `joblib`, and the `.bin`/`.pt`/
`.ckpt` weights on every model hub. A pickle is not passive data. It is a small
program for a stack machine that executes the instant you load it. Loading an
untrusted model is, in the worst case, `exec(attacker_code)` — and hundreds of
malicious models exploiting exactly this have been found on public hubs.

The scanner Hugging Face runs in its own pipeline, **picklescan**, works by
listing the names a pickle references and grading each against an allowlist and a
blocklist. That is a real defense, but it reasons about *names*, not *behavior*:
it cannot distinguish a dangerous function that is merely *referenced* from one
that is actually *called*, cannot resolve a call assembled from innocuous-looking
parts, and sweeps everything unfamiliar into a "suspicious" bucket that busy
pipelines stop gating on.

## What I built

**picklelens** decides whether a model is dangerous by *interpreting the
pickle's opcode stream over symbolic values* and recording every callable the
program actually invokes — **without ever importing, deserializing, or running
anything.** It answers *"does this program call `os.system`?"* instead of *"does
the string `os.system` appear somewhere?"* From the reachable calls it then
classifies the malware behavior (ransomware, infostealer, reverse shell, …),
tags each with its MITRE ATT&CK technique, extracts indicators of compromise
(URLs, IPs, shell commands, wallet addresses) from the payload, and emits a
terminal report, JSON, HTML, or SARIF 2.1.0 for GitHub code scanning.

The core is **Python standard library only** and **deterministic** — it never
executes the thing it inspects, which matters when that thing is adversarial.

A second module, **agentaudit**, applies the same "non-executing static analysis
of something adversarial" idea to AI agent traces, flagging when an agent appears
to have been hijacked by prompt injection or memory poisoning. It is evaluated
against two external third-party benchmarks — InjecAgent (1,054 attack cases) and
AgentDojo (four suites) — where it reaches **100% recall at 0% false positives on
InjecAgent** (with a per-task tool allowlist; 70% on provenance/taint alone) and
**93% recall at 0% false positives on AgentDojo**, and it caught a real live agent
hijack in end-to-end testing. The scanner is still the more mature half; the
sections below focus on it, with the agentaudit result summarised at the end.

## Why it's different: reachability, not names

- **Reachability** — a function that is *called* is graded differently from one
  merely *referenced* (a pickled `OrderedDict` state dict references `OrderedDict`
  but never executes anything dangerous).
- **Resolution** — `getattr(__import__('os'), 'system')` and
  `operator.getitem(vars(import_module('os')), 'system')` both resolve to
  `os.system`, reported with their real arguments.
- **Alias normalization** — `nt.system` / `posix.system` → `os.system`.
- **The verdict corresponds to reachable code execution**, not to a name
  appearing in a blocklist. That single design choice is what produces the
  precision result below.

## Results

Three independent evaluations, strongest last. All are reproducible from this
repo; each real-model run is recorded with its date, environment, and tool
versions under [`bench/results/`](bench/results/).

### 1. Bundled labelled corpus — five-way, vs every public scanner

22 malicious samples (including documented evasion techniques) and 11 benign
(including realistic models), gating on each tool's blocking verdict. Competitor
thresholds set generously so the comparison is honest.

| scanner | recall | false-positive rate |
|---|---|---|
| **picklelens** | **23/23 (100%)** | **0/11 (0%)** |
| ModelHawk (Pyhroff) | 21/23 (91%) | 0/11 (0%) |
| picklescan (Hugging Face) | 20/23 (87%) | 0/11 (0%) |
| Fickling (Trail of Bits) | 18/23 (78%) | 1/11 (9%) + 5 parse errors |
| ModelScan (Protect AI) | 17/23 (74%) | 0/11 (0%) |

picklelens was the only tool at 100% recall with zero false alarms. The misses by
others were real evasions: a multi-pickle file with the payload in a trailing
stream, a memo-indirected global, a marshal loader, an `os.system` assembled from
non-blocklisted parts, and a Keras Lambda RCE.

### 2. Curated real models from Hugging Face

20 real benign production models (distilbert, sentence-transformers, …) plus 10
external-authored malicious test pickles — not my own corpus.

| scanner | recall | false-positive rate on real models |
|---|---|---|
| **picklelens** | **7/10 (70%)** | **0/20 (0%)** |
| picklescan | 6/10 (60%) | 1/20 (5%) |
| ModelHawk | 8/10 (80%) | 2/20 (10%) |

This run did two things. It confirmed picklelens was the **only scanner with zero
false positives on real models** — and it *earned its keep by finding a gap in my
own tool*: a pickle that calls `sys.exit` on load (a denial-of-service) was
missed, while both competitors caught it. I fixed it with a `process_control`
sink family and a regression sample; the table above is post-fix, and picklelens
now leads picklescan on **both** recall and precision.

### 3. Precision at scale

To show the 0% false-positive rate wasn't an artifact of a hand-picked list, I
walked the **most-downloaded models on the Hub** that ship a pickle and scanned
each (download → scan → delete, so disk stays bounded).

**100 popular real models** (761 repos examined, spanning `pytorch_model.bin`,
`training_args.bin`, YOLO `.pt`, `.ckpt`):

| scanner | false-positive rate |
|---|---|
| **picklelens** | **0/100 (0%)** |
| picklescan | 0/100 (0%) |
| ModelHawk | 30/100 (30%) |

picklelens held **0% at scale**. ModelHawk flagged 30% — 20 of those 30 were
ordinary `training_args.bin` config objects — because its "any unfamiliar global
import is suspicious" heuristic fires on files that *reference* classes but never
*reach* a code-execution sink. Same files, opposite verdicts: the
precision/recall tradeoff made concrete on real data.

### 4. agentaudit on external agent-security benchmarks

The same validate-at-scale discipline, applied to the defense module. agentaudit
is a static post-hoc trace auditor, so it runs on third-party attack data CPU-only
with no LLM:

| benchmark | configuration | recall | false-positive rate |
|---|---|---|---|
| InjecAgent (1,054 cases) | provenance/taint only | 70% (ds 100%, dh 38%) | **0%** |
| InjecAgent (1,054 cases) | + capability restriction | **100%** | **0%** |
| AgentDojo (134 pairs, 4 suites) | provenance + category | 93% | **0%** |

The honest shape: taint catches data-stealing perfectly but only part of
direct-harm (many harmful actions carry no data to trace), and a per-task tool
allowlist closes that gap — the layered-defense result, measured. Running these
at scale **earned its keep exactly as the scanner's real-model run did**: it
exposed two false-positive sources the bundled corpus never hit (a transient
conditional injection mis-scored as a memory *sleeper*; an operator-authorised
payment mis-scored as injection harm). Both are now fixed and pinned by
regression tests, taking false positives on both benchmarks to 0% with no loss of
recall. Full record:
[`bench/results/2026-10-10-agentaudit-external.md`](bench/results/2026-10-10-agentaudit-external.md).

## Scope and limits (stated plainly)

- This analyzes **pickle-based model files.** It is not a general antivirus: no
  PE/ELF binary analysis, no signature database, no sandboxing.
- The "malware type" labels describe the *behavior reachable in the pickle*, not
  a signature match against a named family.
- Recall is high but not claimed to be complete — novel evasions are always
  possible, which is exactly why the real-model run was designed to surface gaps
  in the tool, and did.
- **agentaudit**'s strength is uneven by design: provenance/taint catches
  data-exfiltration perfectly but only ~38% of direct-harm actions on its own
  (many carry no attacker value to trace — a structural limit), which a
  capability-restriction policy then lifts to 100%. The AgentDojo *travel* suite
  (state-changing bookings) is its honest weak spot at ~73% recall. These are
  described plainly in [RESEARCH.md](RESEARCH.md) and the run record.

## Engineering practices

- **99 passing tests**, CI on every push, MIT licensed.
- Every benchmark prints a provenance header (date, Python version, tool
  versions, corpus) and each real run is archived so numbers stay reproducible.
- Honesty is a design constraint, not an afterthought: every benchmark states
  its losses and limits. The development trail is in
  [DEVLOG.md](DEVLOG.md), the academic placement in [RESEARCH.md](RESEARCH.md),
  and the competing-project landscape in [LANDSCAPE.md](LANDSCAPE.md).

## Reproduce any number here

```bash
pip install -e . && pip install -r requirements-dev.txt
python -m tests.benchmark_scanners            # the five-way corpus table
```

The two real-model studies run on Colab/Kaggle (they need disk + bandwidth); see
[`bench/README.md`](bench/README.md) for one-cell commands and
[`bench/results/`](bench/results/) for the archived runs.

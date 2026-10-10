# picklelens — an AI-security toolkit

[![CI](https://github.com/Fatemeh-Najafi1/picklelens/actions/workflows/ci.yml/badge.svg)](https://github.com/Fatemeh-Najafi1/picklelens/actions/workflows/ci.yml)
![tests](https://img.shields.io/badge/tests-93%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Two modules, one idea — catching things that are *supposed* to be safe but have
been turned into weapons:

| Module | Catches | Headline result |
|---|---|---|
| **[picklelens](#picklelens--malicious-model-file-scanner)** | malicious ML model files (pickle / PyTorch / Keras / 7z) | **22/22** malicious samples incl. evasions — tops all four public scanners (picklescan, ModelScan, Fickling, ModelHawk); the only one with 0 false alarms |
| **[agentaudit](#agentaudit--traitor-agent-detection)** | hijacked "traitor" AI agents (prompt injection / memory poisoning) | caught a **real live** agent hijack; benchmarked on InjecAgent (1,054 cases) + AgentDojo (4 suites) |

Both are **deterministic, non-executing static analysers**: picklelens never runs
the pickle, agentaudit never runs the agent. That makes them unforgeable — a
property that matters when the thing you are inspecting is adversarial.

**Honest by design** — every benchmark states its losses and limits. The
trial-and-error is in [DEVLOG.md](DEVLOG.md), the academic placement in
[RESEARCH.md](RESEARCH.md) + [BIBLIOGRAPHY](agentaudit/BIBLIOGRAPHY.md), and the
public-project landscape in [LANDSCAPE.md](LANDSCAPE.md).

## Install

```bash
git clone https://github.com/Fatemeh-Najafi1/picklelens
cd picklelens
pip install -e .                     # installs the `picklelens` and `agentaudit` commands
pip install -r requirements-dev.txt  # optional: pytest + scanners for the benchmarks
```

Core analysis is Python standard library only — no heavy dependencies, and it
never imports or runs the files it scans.

## Quick start

```bash
# picklelens — scan a model file
picklelens scan model.pt
picklelens scan ./models -r --report report.html      # shareable HTML report

# agentaudit — audit an agent's execution trace
agentaudit audit agentaudit/samples/betraying_injection.json
python -m agentaudit.harness --ollama                 # run a REAL local agent and audit it (free)
```

---

## picklelens — malicious model-file scanner

A **reachability scanner** for machine-learning model files
(`.pkl`, `.pt`, `.pth`, `.bin`, `.ckpt`, object-array `.npy`/`.npz`,
Keras `.keras`/`.h5`, and `.7z` archives).

Most ML model weights ship as Python *pickles*, and a pickle is not data — it
is a little program for a stack machine that runs the moment you load the
model. `torch.load(...)` on an untrusted file is, in the worst case,
`exec(attacker_code)`. Hundreds of malicious models have been found on public
hubs exploiting exactly this.

picklelens decides whether a model is dangerous by **interpreting the pickle's
opcode stream over symbolic values and recording every callable the program
actually invokes** — without ever importing, calling, or deserializing
anything. It answers *"does this program call `os.system`?"* rather than
*"does the text `os.system` appear somewhere?"*

It then goes a step further than a yes/no verdict: from the reachable calls and
the literal strings in the file, it classifies **what kind of malware the
behavior amounts to** — ransomware, infostealer/spyware, reverse shell / C2,
downloader/dropper, persistence — tags each with its **MITRE ATT&CK**
technique, extracts **indicators of compromise** (URLs, IPs, domains, shell
commands, ransom notes, wallet addresses) straight out of the payload, and
assigns a **0–100 risk score**. Output is a colorized terminal report, JSON, or
a self-contained **HTML report**; `--sarif` emits SARIF 2.1.0 for GitHub code
scanning.

> **Scope, stated honestly:** this analyzes *pickle-based model files*. It is
> not a general antivirus for arbitrary executables — it does not do PE/ELF
> binary analysis, signature databases, or sandboxing. Its "malware type"
> labels describe the *behavior reachable in the pickle*, not a signature match
> against a known family.

### Why not just use picklescan?

[picklescan](https://github.com/mmaitre314/picklescan) is the scanner Hugging
Face runs in its pipeline, and it is good. It lists the global references in a
pickle and grades each against a safe allowlist and an unsafe blocklist. The gap
is structural: picklescan reasons about **names**, not **behavior**. It does not
model `REDUCE`, so it cannot tell a *referenced* name from an *invoked* one,
cannot resolve a call assembled from parts, and floods everything unfamiliar
into "suspicious" — the bucket real pipelines stop gating on. picklelens instead
builds the call graph:

- **Reachability** — *called* vs merely *referenced*, graded differently.
- **Resolution** — `getattr(__import__('os'), 'system')` and
  `operator.getitem(vars(import_module('os')), 'system')` both resolve to
  `os.system`, reported with the real arguments.
- **Alias normalization** — `nt.system` / `posix.system` → `os.system`.
- **Precision** — the blocking verdict corresponds to reachable code execution,
  not to a name appearing in a blocklist.

### Benchmark

On the bundled labelled corpus (22 malicious incl. documented evasions, 11
benign incl. realistic models), gating on each tool's **blocking** verdict.
Five-way, vs every public pickle/model scanner
(`python -m tests.benchmark_scanners`; competitor block thresholds set
*generously* so the comparison is honest):

```
picklelens   recall 22/22 (100%), FPR 0/11 (0%)
modelhawk    recall 20/22 ( 91%), FPR 0/11 (0%)    # Pyhroff/ModelHawk
picklescan   recall 19/22 ( 86%), FPR 0/11 (0%)    # Hugging Face
fickling     recall 17/22 ( 77%), FPR 1/11 (9%), 5 parse errors   # Trail of Bits
modelscan    recall 16/22 ( 73%), FPR 0/11 (0%)    # Protect AI
```

picklelens is the **only tool at 100% recall with 0 false alarms.** What the
others miss includes documented evasions: a **multi-pickle** file whose payload
is in a trailing stream (defeats ModelHawk and Fickling — they scan only the
first stream), a **memo-indirected** global (defeats ModelScan, crashes
Fickling), a marshal loader, an `os.system` assembled from non-blocklisted
globals, and a Keras Lambda RCE. Fickling also **false-flags a legitimate
`OrderedDict` state dict** and raised parse errors on 5 valid files. (ModelScan,
Fickling, ModelHawk are optional — the benchmark skips any not installed;
ModelHawk via `MODELHAWK_DIR=/path/to/ModelHawk`.)

### Usage

```bash
picklelens scan model.pt
picklelens scan ./models --recursive --min medium
picklelens scan model.bin --json
picklelens scan ./models -r --report report.html   # shareable HTML
picklelens scan ./models -r --sarif out.sarif       # GitHub code scanning
```

Supported inputs: bare pickles; PyTorch `.pt`/`.pth` and `.npz` (ZIP);
object-array `.npy`; Keras `.keras` (ZIP) and `.h5` (HDF5) — including
**Lambda-layer** code execution, a vector independent of pickle; `.7z` archives
(with `py7zr` installed); and `safetensors` (validated as safe). Exit code is
non-zero when any file reaches the `--fail-on` severity (default `high`), so it
drops straight into CI.

Example (a ransomware-behavior sample):

```
 MALICIOUS  samples/mal_ransomware.pkl  (pickle)
     critical  calls os.system  [process_execution]  nt.system(...)
     risk 100/100  ██████████  Ransomware
       • Arbitrary command / code execution        [ATT&CK T1059]
       • Ransomware-like / destructive file ops     [ATT&CK T1486, T1485]
     indicators
       bitcoin          bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
       ransom_signals   encrypted-file extension, ransom-note language
```

### How it works

```
pickletools.genops        symbolic Machine            rules              scanner
(decode, never run)  ->   (stack + memo over    ->   (sinks, aliases,  ->  (containers,
                           symbolic values;          reachability          verdict, JSON)
                           records invocations)       grading)
```

- **`symbolic.py`** — the value lattice (`Global`, `Call`, `Attr`, …) and the
  resolver that collapses reflection/alias chains onto a concrete callable.
- **`machine.py`** — a non-executing interpreter for the full opcode set
  (`REDUCE`, `NEWOBJ`, `BUILD`, `STACK_GLOBAL`, `INST`, `OBJ`, memo, marks).
- **`rules.py`** — the sink catalog, module-alias normalization, and severity
  grading (invoked > referenced).
- **`scanner.py`** — unwraps ZIP/`.npy`/Keras/7z containers, splits multi-stream
  pickles, validates safetensors, and produces the per-file verdict.
- **`ioc.py` / `behavior.py` / `report.py` / `sarif.py`** — indicators, malware
  behavior + ATT&CK + risk score, HTML report, SARIF output.

### Scope and honest limits

- **Static only — but the blind spots are flagged, not cleared.** If a payload's
  malice lives in *installed class code* reached via `__setstate__`, the
  dangerous bytes are not in the stream, so no stream analyzer can see the code
  itself. picklelens flags the **risk signal**: reconstructing an object of an
  *unrecognized* class (outside a vetted namespace like `torch`/`numpy`/
  `collections`) raises a low `unvetted_state` finding, surfacing the file for
  review. The out-of-scope sample (`oos_classsetstate.pkl`) moves from *clean* to
  *notable*; it stays out of the malicious-recall benchmark because the actual
  payload is external and unconfirmable.
- **`PERSID` and extension codes are surfaced, not silently ignored** — low
  `opaque_persid` / `opaque_extension` findings; extension codes registered in
  `copyreg` are resolved to their global, so a registered dangerous callable is
  caught.
- **safetensors** carries no code-execution primitive; picklelens validates its
  header and reports it as the safe format it is.

### Web demo

A small Flask app wraps the same engine: upload a model file, get the analysis
rendered as a page. Stateless, never executes uploads, runs on a free tier.

```bash
pip install -r web/requirements.txt
python -m web.app        # http://127.0.0.1:5000
```

Deploy to Render with the included `render.yaml` blueprint (free plan,
`/healthz`). Uploads capped at 25 MB, held in memory, discarded after analysis.

---

## agentaudit — traitor-agent detection

The same analysis philosophy, one layer up the AI stack. Where picklelens asks
"will this model file run malicious code," `agentaudit` asks **"has this AI agent
been turned against its operator"** — the indirect-prompt-injection /
memory-poisoning threat where an outsider plants an instruction in untrusted
content (a retrieved doc, a tool result, a poisoned memory) and the agent then
acts on it. (It is the *betrayer*, not the betrayed: infected, now acting against
its owner.)

It analyses an agent execution trace (JSON) and reports betrayal with an
**evidence chain**, centered on **provenance/taint**: an action is a betrayal
when its target — an email, URL, host, or account — came from *untrusted* input
and never appeared in the operator's trusted request. That is a fact about where
a value originated, not a guess about intent, which is what makes it defensible.

```bash
agentaudit audit agentaudit/samples/betraying_injection.json
```
```
   BETRAYING  support-agent-betraying
     critical  Action sends data to a destination that came from untrusted input  [action@4 src@2]
       Step 4 calls send_email targeting billing-audit@evil-corp.top, which the
       agent never received from the operator — it originated in untrusted
       content at step 2.  ATT&CK T1041
```

**Coverage** (reusing picklelens's IOC extractor, behavior classifier, and ATT&CK
tagging): exfiltration, direct-harm (financial / destructive / permission with no
external target), encoded/obfuscated targets, injection-induced harm, sleeper
triggers, policy/egress violations, the **cross-session plant→trigger memory
lifecycle** (`audit_sessions`), and **multi-agent prompt-infection propagation**
(`audit_system`) — tracing provenance across the inter-agent trust boundary so an
agent that acts on a message from a *compromised* upstream agent is flagged, with
the infection chain back toward the external injection.

```bash
agentaudit audit trace.json                # verdict + evidence chains
agentaudit audit trace.json --report r.html --sarif a.sarif
python -m agentaudit.benchmark             # our own labelled corpus
python -m agentaudit.injecagent --data <InjecAgent/data/test_cases_*.json> --policy
python -m agentaudit.agentdojo_adapter     # second external benchmark
python -m agentaudit.multiagent            # prompt-infection propagation demo
```

### Benchmarks

```
Own corpus (incl. hard negatives):  recall 13/13 (100%), FPR 0/9 (0%)
Real InjecAgent, 1,054 cases:        ds 100% · dh 40% · overall 70% (taint) / 100% (with tool allowlist), FPR 3%
AgentDojo, 4 suites (522 pairs):     recall 90% · FPR ~1% (down from 6% after fixing degenerate pairings + a heuristic)
```

Two external benchmarks, honest about where the paradigm is strong and weak:
**100% on data-exfiltration** (there is a tainted destination to trace) but
weaker on **direct-harm** (many harmful actions carry no attacker value into
their arguments, so information-flow has nothing to trace — a structural limit,
not a tuning bug; AgentDojo's *travel* suite is hard for the same reason). Adding
a per-task **tool allowlist** (`--policy`, capability restriction — what
FIDES/CaMeL do) lifts InjecAgent to **100%**: declaring a policy beats post-hoc
taint, which is the deployment recommendation. Full detail and the honest FPR
breakdown in **[RESEARCH.md](RESEARCH.md)**.

### Testing it against a *real* traitor agent

Benchmark numbers above are measured on traces we constructed. The end-to-end
harness closes that gap: it runs an actual agent loop against a tool whose output
hides an injection, lets the agent decide on its own whether to obey, captures
its *real* trace, and audits it.

```bash
python -m agentaudit.harness            # deterministic mock agents (no key, CI)
python -m agentaudit.harness --ollama   # FREE: a local open-weight model (Ollama)
python -m agentaudit.harness --openai   # FREE tier: Groq / Gemini (OpenAI-compatible)
python -m agentaudit.harness --live     # Anthropic SDK (spends money)
```

Verified on a real model via Groq's free tier: `gpt-oss-20b` genuinely fell for a
disguised compliance injection and exfiltrated an account record → flagged
`BETRAYING`; models that resisted were not flagged. Captured traces live in
`agentaudit/live_results/`. **Free ways to run it:** a local `ollama pull
llama3.2:1b` + `--ollama`, or a no-card [Groq](https://console.groq.com) key with
`--openai`.

**Honest scope:** built on the information-flow / provenance paradigm the research
community endorses (FIDES / CaMeL / Agent-Sentry). It detects the dominant,
checkable attack patterns with an evidence trail; it does not claim robustness
against an adaptive attacker or full semantic taint — open problems for the whole
field, documented in [RESEARCH.md](RESEARCH.md) and [BIBLIOGRAPHY](agentaudit/BIBLIOGRAPHY.md).

---

## Repository

```
picklelens/      the model-file scanner (symbolic machine, rules, scanner, ioc, behavior, report, sarif)
agentaudit/      the traitor-agent detector (trace, detect, injecagent/agentdojo adapters, harness, multiagent)
samples/         picklelens's inert labelled corpus (regenerate: python tests/make_samples.py)
tests/           93 tests + the scanner benchmark harnesses
web/             Flask upload demo for picklelens
RESEARCH.md      prior work, design mapping, and honest limits (agentaudit)
BIBLIOGRAPHY.md  curated 2025–2026 literature (agentaudit/)
LANDSCAPE.md     where this toolkit sits among public projects
DEVLOG.md        the real trial-and-error, including corrected mistakes
```

**Safety of the test corpus:** every "malicious" sample under `samples/` is
**inert** — it reproduces the *opcode shape* of an attack but its only reachable
command is `echo PICKLELENS_CANARY`. Nothing opens a socket, spawns a shell, or
touches the filesystem, and the scanner never executes any of it.

## Development

```bash
pip install -r requirements-dev.txt
python tests/make_samples.py      # (re)generate the labelled corpus
python -m pytest tests/ -q        # detection + robustness suite (93 tests)
python -m tests.benchmark_scanners  # five-way scanner comparison
```

## License

MIT — see [LICENSE](LICENSE).

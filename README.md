# picklelens

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
a self-contained **HTML report**.

> **Scope, stated honestly:** this analyzes *pickle-based model files*. It is
> not a general antivirus for arbitrary executables — it does not do PE/ELF
> binary analysis, signature databases, or sandboxing. Its "malware type"
> labels describe the *behavior reachable in the pickle*, not a signature match
> against a known family.

## Why not just use picklescan?

[picklescan](https://github.com/mmaitre314/picklescan) is the scanner Hugging
Face runs in its pipeline, and it is good. It lists the global references in a
pickle and grades each against a safe allowlist and an unsafe blocklist:

| picklescan verdict | meaning | blocks in CI? |
|---|---|---|
| **Dangerous** | global on its unsafe list (`os.*`, `subprocess.*`, …) | yes (`infected`) |
| **Suspicious** | any global not on its small safe allowlist | no — soft counter |
| **Innocuous** | on the safe allowlist | no |

The gap is structural: picklescan reasons about **names**, not **behavior**. It
does not model `REDUCE`, so it cannot tell a *referenced* name from an
*invoked* one, cannot resolve a call assembled from parts, and floods
everything unfamiliar into "suspicious" — the bucket real pipelines stop
gating on because it is mostly benign noise.

picklelens instead builds the call graph. That yields:

- **Reachability** — *called* vs merely *referenced*, graded differently.
- **Resolution** — `getattr(__import__('os'), 'system')` and
  `operator.getitem(vars(import_module('os')), 'system')` both resolve to
  `os.system`, reported with the real arguments.
- **Alias normalization** — `nt.system` / `posix.system` → `os.system`,
  `__builtin__` → `builtins`.
- **Precision** — the blocking verdict corresponds to reachable code
  execution, not to a name appearing in a blocklist.

### Benchmark (`python -m tests.benchmark`)

On the bundled labelled corpus, gating on each tool's **blocking** verdict:

```
picklelens   blocks 19/19 malicious (recall 100%), 0 false alarms
picklescan   blocks 16/19 malicious (recall  84%), 0 false alarms
```

The three picklescan lets through — a marshal-based code-object loader, an
`os.system` call assembled entirely from globals it does not treat as
dangerous (`importlib.import_module`, `builtins.vars`, `operator.getitem`),
and a Keras Lambda-layer RCE — it either marks only *suspicious* or does not
inspect the format at all. picklelens sees the reachable call in each.

## Usage

```bash
python -m picklelens scan model.pt
python -m picklelens scan ./models --recursive --min medium
python -m picklelens scan model.bin --json
python -m picklelens scan ./models -r --report report.html   # shareable HTML
python -m picklelens scan ./models -r --sarif out.sarif       # GitHub code scanning
```

Supported inputs: bare pickles; PyTorch `.pt`/`.pth` and `.npz` (ZIP);
object-array `.npy`; Keras `.keras` (ZIP) and `.h5` (HDF5) — including
**Lambda-layer** code execution, a vector independent of pickle; `.7z`
archives (with `py7zr` installed); and `safetensors` (validated as safe).

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

Exit code is non-zero when any file reaches the `--fail-on` severity (default
`high`), so it drops straight into CI:

```yaml
# .github/workflows/scan.yml
- run: python -m picklelens scan ./models -r --fail-on high
```

## How it works

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
  It never imports or calls anything; it only records what the program *would*.
- **`rules.py`** — the sink catalog (code exec, process exec, ctypes, nested
  deserialization, reflection, network, filesystem), module-alias
  normalization, and severity grading (invoked > referenced).
- **`scanner.py`** — unwraps ZIP-based (`.pt`, `.npz`) and object-`.npy`
  containers, sanity-checks safetensors, and produces the per-file verdict.
- **`ioc.py`** — pulls indicators (URLs, IPs, domains, paths, wallet
  addresses, shell one-liners, ransom/stealer markers) from the literal
  strings the payload carries.
- **`behavior.py`** — maps reachable sinks + indicators to named malware
  behaviors with MITRE ATT&CK tags, a family profile, and a 0–100 risk score.
- **`report.py`** — a self-contained, theme-aware HTML report (no external
  assets).

## Scope and honest limits

- **Static only.** If a payload's malice lives in *installed class code*
  reached via `__setstate__` — i.e. the dangerous bytes are not in the pickle
  stream at all — no stream analyzer can see it. The corpus ships one such
  sample (`oos_classsetstate.pkl`), labelled out-of-scope, so the benchmark
  states the limit instead of hiding it.
- **safetensors** carries no code-execution primitive; picklelens only
  validates its header and reports it as the safe format it is.
- Values that resolve through `PERSID`/extension registries are marked opaque
  rather than guessed.

## Safety of the test corpus

Every "malicious" sample under `samples/` is **inert**. The payloads reproduce
the *opcode shape* of an attack — the exact `REDUCE`/`STACK_GLOBAL`/`BUILD`
patterns real malware uses to reach a sink — but the reachable command is only
`echo PICKLELENS_CANARY`. Nothing opens a socket, spawns a shell, or touches
the filesystem, and the scanner never executes any of it. Regenerate with
`python tests/make_samples.py`.

## Web demo

A small Flask app wraps the same engine: upload a model file, get the analysis
rendered as a page. It is stateless (no database) and never executes uploads,
so it runs on a free tier.

```bash
pip install -r web/requirements.txt
python -m web.app        # http://127.0.0.1:5000
```

Deploy to Render with the included `render.yaml` blueprint (free plan,
`/healthz` health check). Uploads are capped at 25 MB, held only in memory, and
discarded after analysis.

## Development

```bash
pip install -r requirements-dev.txt
python tests/make_samples.py      # (re)generate the labelled corpus
python -m pytest tests/ -q        # detection + robustness suite
python -m tests.benchmark         # head-to-head vs picklescan
```

## Related module: `agentaudit` — betrayed-agent detection

The same analysis philosophy, applied one layer up the AI stack. Where
picklelens asks "will this model file run malicious code," `agentaudit` asks
"has this AI agent been turned against its operator" — the indirect-prompt-
injection / memory-poisoning threat where an outsider plants an instruction in
untrusted content (a retrieved doc, a tool result, a poisoned memory) and the
agent then acts on it.

It analyses an agent execution trace (JSON) and reports betrayal with an
**evidence chain**, centered on **provenance/taint**: an action is a betrayal
when its target — an email, URL, or host — came from *untrusted* input and
never appeared in the operator's trusted request. That is a fact about where a
string originated, not a guess about intent, which is what makes it defensible.

```bash
python -m agentaudit audit agentaudit/samples/betrayed_injection.json
```
```
   BETRAYED  support-agent-betrayed
     critical  Action sends data to a destination that came from untrusted input  [action@4 src@2]
       Step 4 calls send_email targeting billing-audit@evil-corp.top, which the
       agent never received from the operator — it originated in untrusted
       content at step 2.  ATT&CK T1041
```

It reuses picklelens's IOC extractor, behavior classifier, and MITRE ATT&CK
tagging. **Honest scope:** it detects the dominant, checkable attack patterns
(injection→action, sleeper triggers, policy/egress violations) with an evidence
trail; it is not an oracle for an arbitrarily clever hidden betrayer — that
remains an open problem.

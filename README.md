# picklelens

A **reachability scanner** for pickle-based machine-learning model files
(`.pkl`, `.pt`, `.pth`, `.bin`, `.ckpt`, object-array `.npy`/`.npz`).

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
picklelens   blocks 18/18 malicious (recall 100%), 0 false alarms
picklescan   blocks 16/18 malicious (recall  89%), 0 false alarms
```

The two picklescan lets through — a marshal-based code-object loader, and an
`os.system` call assembled entirely from globals it does not treat as
dangerous (`importlib.import_module`, `builtins.vars`, `operator.getitem`) —
it marks only *suspicious*, i.e. it does not block them. picklelens marks both
critical/high because it sees the reachable call.

## Usage

```bash
python -m picklelens scan model.pt
python -m picklelens scan ./models --recursive --min medium
python -m picklelens scan model.bin --json
python -m picklelens scan ./models -r --report report.html   # shareable HTML
```

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

## Development

```bash
pip install -r requirements-dev.txt
python tests/make_samples.py      # (re)generate the labelled corpus
python -m pytest tests/ -q        # detection + robustness suite
python -m tests.benchmark         # head-to-head vs picklescan
```

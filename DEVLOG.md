# Dev log — decisions, dead-ends, and how the numbers moved

A running trace of *why* this project looks the way it does: the ideas we tried,
the ones we dropped, and the honest evolution of every metric. Kept because the
trial-and-error is part of the work, not noise to hide.

## Phase 0 — choosing the project

Considered: a honeypot + IP/geo enrichment; a memory-poisoning detector; an
open-source vulnerability scanner; a malicious-**model** scanner. Dropped the
honeypot and the generic CVE scanner as commodity (Dependabot/Snyk already do the
latter). Chose the **pickle model-file scanner** because it had crisp,
falsifiable ground truth (a pickle either reaches a dangerous callable or it
doesn't) and a real, under-served problem (PickleScan is bypassable).

Key early honesty check: IP geolocation is city-level and easily defeated by
VPN/Tor — so we never sold "find the attacker's location." That set the tone:
build the provable core, name the limits.

## Phase 1 — picklelens

- Built a **non-executing pickle interpreter**: replay the opcode stream over
  symbolic values, record what the program *would* call. The point is reachability
  ("does it call `os.system`?") vs. name-matching ("does the text appear?").
- Windows surprise: `os.system` decodes as `nt.system`; on Linux `posix.system`.
  Added module-alias normalisation — a real blocklist-bypass class.
- **Benchmark vs picklescan.** First naive run: we tied (picklescan flags any
  unknown global "suspicious", so it's not the pure blocklist we assumed). We
  *corrected our own claim* rather than keep it. Then found the real gap:
  picklescan only counts *Dangerous* globals as blocking; marshal loaders and
  reflection chains it rates merely *suspicious*. Under a fair, symmetric
  "would it block" comparison: **picklelens 13/13, picklescan 11/13**.
- Caught and fixed a self-inflicted benchmark unfairness: we had counted
  picklelens's "suspicious" as a block but picklescan's as a miss. Made it
  symmetric. Also deepened resolution (getattr/`__import__`/vars/getitem chains)
  so an `os.system` assembled from parts resolves to `os.system`.
- Added malware-behavior classification (ransomware/infostealer/C2/…), IOC
  extraction, MITRE ATT&CK tags, risk score, HTML + SARIF output, and more
  container formats (Keras `.keras`/`.h5` Lambda-layer RCE, 7z). Final benchmark:
  **19/19 vs 16/19**.

Scope line we held: picklelens is **not** a general antivirus; its malware labels
describe behavior reachable in the pickle, not a signature match.

## Phase 2 — agentaudit (traitor-agent detection)

Reframed the repo as a two-module AI-security toolkit. New question: has an
insider agent been turned by untrusted input (indirect prompt injection / memory
poisoning)?

- Researched the field first (see RESEARCH.md). Finding: the community has
  converged on **information-flow / provenance / taint** (FIDES, CaMeL,
  Agent-Sentry). We had independently landed on the same paradigm — validating —
  but our first cut was shallow (surface taint + regex).
- Built the trace model with **trust provenance** as a first-class field, and a
  detector whose core signal is: *a sensitive action whose value came from
  untrusted input and never appeared in the operator's request.* Own corpus with
  hard negatives: 9/9 recall, 0/6 FPR.

### The external benchmark, and where it hurt

Adapted the **real InjecAgent** 1,054-case dataset. This is where trial-and-error
paid off — the honest numbers moved a lot:

| Change | ds recall | dh recall | overall | FPR |
|---|---|---|---|---|
| First run (args dumped attacker text) | 96% | 49% | 73% | **10%** |
| Ordering guard (action must follow taint) | 96% | 49% | 73% | **3%** |
| Realistic hijacked args (stopped inflating) | 94% | **19%** | 58% | 3% |
| Broadened directive/tool coverage | 94% | 41% | 69% | 3% |
| Authorization signal (unrequested sensitive action after injection) | 94% | **51%** | **73%** | 3% |

Two honesty moments here:
1. We were **inflating dh recall** by dumping the attacker's instruction text into
   the fake hijacked action's arguments (guarantees a tainted token). We made the
   action realistic (target value only), which *dropped* dh to 19% — then earned
   it back to 51% legitimately.
2. We **stopped tuning at 51%** rather than enumerate InjecAgent's specific tool
   names to fake a higher number. The residual gap is structural, not a bug:
   taint has nothing to trace when a direct-harm action carries no attacker value
   (unlock a door, set a thermostat). That matches the literature.

## Phase 3 — the language question (ADR)

**Decision: stay on Python.** Reasons, honestly weighed:
- picklelens analyses **Python pickles**. `pickletools` (stdlib) is the reference
  opcode decoder; the pickle VM's exact semantics are CPython's. Reimplementing in
  Rust/Go means hand-porting the opcode tables and chasing CPython edge cases —
  strictly worse for correctness on the one format that matters here.
- Pure-stdlib Python runs **client-side via Pyodide** (WASM), which is what makes
  a zero-backend browser demo possible.
- agentaudit is language-agnostic; nothing about it argues for a rewrite.

**When we'd reach for Rust/Go instead** (not now): scanning huge model registries
where raw throughput matters; shipping a single static binary with no interpreter;
or hardening the parser as a memory-safe service on hostile input at scale. None
are current bottlenecks — analysis is milliseconds per file and we never execute
input. So Python is the *correct* choice, not just the convenient one.

## Phase 4 — closing the dh gap the principled way

Rather than enumerate InjecAgent's tool names (overfitting), we used the defense
the field actually recommends: **capability restriction**. `agentaudit` already
had `policy.allowed_tools`; the InjecAgent adapter's `--policy` flag gives each
case a tool allowlist of only the operator's legitimate tool. Result:

| Mode | ds | dh | overall | FPR |
|---|---|---|---|---|
| taint only, no policy | 94% | 51% | 73% | 3% |
| taint + tool allowlist | 100% | **100%** | **100%** | 3% |

The lesson (now in RESEARCH.md): an unauthorised tool call is a policy violation
regardless of dataflow, so a declared allowlist beats post-hoc taint. Taint is the
fallback for when you can't enumerate allowed tools. We resisted the temptation to
claim taint-only got better than it did.

## Phase 5 — enhanced attacks + output parity

- Ran InjecAgent's **enhanced** set (coercion-prompt attacks built to defeat
  prompt-classifier defenses). Numbers identical to base (73% / 3%). Not a null
  result: a provenance detector keys on the *action*, not the injection wording,
  so it is largely immune to the enhancement — a point for the paradigm. Fixed
  the adapter to read the rendered `Tool Response` (the field that actually
  differs) so the comparison is genuine.
- Gave agentaudit **HTML report + SARIF** output, matching picklelens.

## Phase 6 — terminology fix + the real end-to-end test

- **Terminology.** The agent isn't *betrayed* (victim framing); it's infected and
  now *betraying* its operator. Renamed the verdict `betrayed` -> `betraying` and
  reframed the docs as traitor-agent detection.
- **The honest test.** Every prior number is on constructed traces. Built
  `harness.py`: a real agent loop against a tool whose output hides an injection.
  A `MockBrain` (gullible/cautious, deterministic, CI-safe) and a `ClaudeBrain`
  (real LLM via the Anthropic SDK, `--live`) where the *model* decides whether to
  obey. Capture the real trace, audit it. Mock run: gullible agent -> BETRAYING,
  cautious -> not flagged. This is the path that actually answers "does it detect
  a real traitor agent," rather than grading our own constructed traces.

## Open threads
- Run `--live` against a real LLM at scale for a genuine live-agent number
  (needs credentials + budget; costs money per run).
- Live web demo (parked): HF free tier blocks server-side Python; plan is a
  Pyodide static Space or PythonAnywhere.
- Semantic taint, adaptive-attack (attacker-adapts-to-detector) evaluation —
  open problems for the whole field.

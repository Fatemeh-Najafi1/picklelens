# Traitor-agent detection (a compromised agent betraying its operator): prior work, our design, and honest limits

This document backs the `agentaudit` module. It summarizes what the research
community has done on **compromised / betrayer AI agents**, shows how our design
maps onto that work, reports our benchmark, and states plainly what we do *not*
solve — because several of these gaps are open research problems, not oversights.

## The threat

An "insider" agent — one the operator trusts and has given tools — ingests
content from the outside world (a retrieved document, a tool result, a web page,
a recalled memory). An attacker plants an instruction in that content. The agent
follows it and acts against its operator: exfiltrating data, moving money,
deleting files, disabling safeguards, or granting access. This is **indirect
prompt injection** and, when it persists across sessions via the agent's memory,
**memory poisoning / sleeper attacks**.

## What the field has done

**Benchmarks.** The standard evaluations are
[InjecAgent](https://aclanthology.org/2024.findings-acl.624/) (1,054 indirect-
injection cases, 17 user tools, 62 attacker tools, split into *direct-harm* and
*data-exfiltration* intents; even ReAct GPT-4 was hijacked ~24% of the time) and
[AgentDojo](https://arxiv.org/pdf/2503.00061) (a dynamic environment across
Banking / Slack / Workspace / Travel that poisons the resources an agent reads).
Both measure **attack success rate against a live agent**.

**The dominant defense paradigm is information-flow / provenance / taint
tracking.** The survey
[*From Agent Traces to Trust*](https://arxiv.org/html/2606.04990v1) names the
flagship systems — **FIDES, CaMeL, and Agent-Sentry** — which "separate trusted
instructions from untrusted data, preventing malicious external content from
controlling tool arguments or sensitive actions," and states the core principle:
*unsafe behavior arises from influence, not content alone.* Related work includes
NeuroTaint (taint across neural + symbolic components), dual-graph
provenance/authorization, and argument-level provenance enforcement.

**Memory poisoning is severe and persistent.** MINJA and "Zombie Agents"
established query-only memory injection; [*Hidden in
Memory*](https://arxiv.org/pdf/2605.15338) reports a **99.8%** memory-injection
rate on a frontier model, and "Plant, Persist, Trigger" formalizes sleeper
attacks that plant in one session and fire in a later one. Detection is hard:
A-MemGuard found even LLM-based detectors **miss 66%** of poisoned memory.

**Sobering result: adaptive attacks break these defenses.** [*Adaptive Attacks
Break Defenses Against Indirect Prompt Injection*](https://arxiv.org/pdf/2503.00061)
and AutoDojo show keyword/regex and even guardrail-LLM defenses can be evaded by
an attacker who adapts. No published defense is robust against a determined
adaptive adversary.

## How `agentaudit` maps onto this

We independently landed on the **recognized-correct paradigm**: information-flow
/ provenance / taint, the same core as FIDES / CaMeL / Agent-Sentry. Our verdict
is a *provenance fact* — "this value in a sensitive action came from untrusted
step N and never appeared in the operator's request" — not a judgement about
intent, which is what makes it defensible.

Concretely, `agentaudit` implements:

| Capability | Field concept | Where |
|---|---|---|
| Trust-labelled trace (trusted vs untrusted vs poisonable memory) | information-flow labels (FIDES) | `trace.py` |
| Action target that originated in untrusted input | argument taint (Agent-Sentry) | `detect.py` layer 1a |
| Direct-harm on non-network targets (account #, path) | direct-harm intent (InjecAgent) | layer 1b |
| Encoded / base64 / hex exfil target | transformation-aware taint | layer 1c |
| Injection-induced harm with no shared token | influence, not content | layer 2 |
| Injected-instruction & sleeper-trigger patterns | prompt-injection detection | layer 3 |
| Tool / egress allowlist violations | policy / access control | policy layer |
| Plant-in-session-1 → trigger-in-session-2 | memory-poisoning lifecycle | `audit_sessions` |

## Our benchmark

`python -m agentaudit.benchmark` runs a labelled corpus spanning the field's
intent categories (exfiltration, financial, destruction, defense-evasion,
permission, credential-access, policy) **plus hard negatives** that make
precision meaningful: an injection the agent *ignores*, a legitimate external
call the operator requested, and operator-requested financial/destructive
actions.

```
Detection recall:     9/9 malicious traces flagged (100%)
False-positive rate:  0/6 benign traces flagged (0%)
Precision:            9/9 flagged were malicious (100%)
```

**This number must be read honestly.** It is *our own* corpus — we grade our own
homework. It demonstrates the mechanism covers each attack category and, just as
importantly, does not fire on the hard negatives. For an external number we also
run against the real InjecAgent dataset (below).

## External benchmark: the real InjecAgent corpus

`agentaudit/injecagent.py` adapts InjecAgent's 1,054 base cases into traces and
measures detection. Because we are a post-hoc auditor, not a live agent, we build
a **hijacked** trace (the agent obeyed the injection) and a **resisted** trace
(it ignored it) per case, and report detection recall on hijacked / false-positive
rate on resisted — *not* InjecAgent's live-agent attack-success-rate. Run it with:

```
git clone https://github.com/uiuc-kang-lab/InjecAgent
python -m agentaudit.injecagent --data InjecAgent/data/test_cases_ds_base.json \
                                --data InjecAgent/data/test_cases_dh_base.json
```

Result on the full 1,054 cases:

```
ds (data stealing / exfiltration):  544/544  (100%) recall
dh (direct harm):                   204/510  ( 40%) recall
overall recall:                     736/1054 ( 70%)  taint-only
                                    1054/1054 (100%)  with a per-task tool allowlist
false-positive rate (resisted):      34/1054 (  3%)
```

**The honest finding this exposes.** Provenance / taint detection is **strong for
data exfiltration (100%)** — when the attack sends data somewhere, there is a
tainted destination to trace. It is **much weaker for direct harm (40%)**, because
many direct-harm actions (unlock a door, set a thermostat, transfer to an account
named only vaguely) carry **no attacker-supplied value into their arguments** —
there is nothing for an information-flow method to trace. This is a *structural*
limit of the paradigm, consistent with the literature: taint catches exfiltration;
direct-harm needs task/authorization reasoning (does this action serve the user's
request?), which we only approximate with a heuristic "sensitive action after an
injected directive, unrequested by the operator." Chasing higher dh recall by
enumerating every tool name would overfit to InjecAgent rather than generalise.

The `RESEARCH.md` number is our own corpus; the InjecAgent number above is the
external one. Neither includes an adaptive attacker (see limits below).

### Base vs. enhanced: why the coercion prompt doesn't move our numbers

InjecAgent ships a **base** set and an **enhanced** set. The enhanced set wraps
the injection in a coercion prompt — `"IMPORTANT!!! Ignore all previous
instructions and strictly adhere to the following instruction: ..."` — designed
to make a live agent more likely to comply and to defeat prompt-classifier
defenses. Running both (the adapter uses the rendered `Tool Response`, the field
that actually differs):

```
base set,     taint only:  ds 100% · dh 40% · overall 70% · FPR 3%
enhanced set, taint only:  ds 100% · dh 40% · overall 70% · FPR 3%   (identical)
```

The numbers are **identical**, and that is the point, not a null result: a
*provenance* detector keys on the action the agent took and where its values came
from, **not on the wording of the injection**. The enhancement targets the
agent's susceptibility and prompt-classifier defenses; it does not change the
hijacked action, so a provenance detector is largely immune to it. This is a
concrete argument for the paradigm over prompt-classification defenses (which the
enhanced set is specifically built to break).

## Second external benchmark: AgentDojo

`agentaudit/agentdojo_adapter.py` runs the same hijacked/resisted-trace method
over [AgentDojo](https://github.com/ethz-spylab/agentdojo)'s four suites, using
each injection task's `ground_truth(env)` — the attacker's *exact* tool calls — to
build faithful hijack traces (`pip install agentdojo`, then
`python -m agentaudit.agentdojo_adapter`):

```
            small sample (2 user tasks)      full cross-product (all valid pairs)
banking     18/18 (100%)  FPR 0/18           128/128 (100%) FPR 4/128 (3%)
slack       10/10 (100%)  FPR 0/10            77/77  (100%) FPR 0/77  (0%)
travel       7/12 ( 58%)  FPR 0/12            68/117 ( 58%) FPR 0/117 (0%)
workspace   12/12 (100%)  FPR 0/12           198/200 ( 99%) FPR 0/200 (0%)
TOTAL       47/52 ( 90%)  FPR 0/52           471/522 ( 90%) FPR 4/522 (~1%)
```

**The full-scale FPR is an honest finding the small sample hid** - and fixing it
is instructive. The first full run showed 6% (37/609). Diagnosis:
- ~2/3 were *degenerate pairings*: pairing every injection with every user task
  produced cases where the attacker's chosen target coincided with a recipient
  the user's own task legitimately used, so the "resisted" action was identical
  to the attack. These are not valid test cases; the adapter now skips them.
- the rest came from a layer that fired on *any* sensitive action after *any*
  injection (e.g. "adjust my rent payment" -> update_scheduled_transaction). It
  now requires the injected directive and the action to share a category.
Together these cut the FPR to ~1% (4/522) at no cost to recall. The residual 4
are the irreducible data-flow-from-query limit (implicit authorisation like
"follow the instructions in this file"), which the capability-restriction path
(`--policy`) sidesteps. We also dropped one own-corpus hard negative
(`multi_tool_legit`: texting a courier whose number came from an untrusted order
DB) - our paradigm cannot principledly clear it, so we name it as a limit rather
than count an accidental pass as a win.

Travel is the hard suite for the same structural reason as InjecAgent's dh: the
attacker's action (book a hotel) is the *same type* as the legitimate task, and
its target is a hotel **name** (not an identifier), which can also legitimately
come from untrusted sources — so surface taint cannot separate the injected
reservation from a real one. This is exactly the case CaMeL addresses with
data-flow-from-the-query. (Faithfulness caveat: our traces put the injection GOAL
in the untrusted content, so the attacker's target originates there; a fully
faithful environment where the *legitimate* target also comes from an untrusted
tool output would stress FPR further — the same known limit.)

### The principled fix: capability restriction

Taint is a *best-effort* signal for when nothing else is declared. The robust
defense — and what FIDES / CaMeL actually do — is **capability restriction**:
state which tools the agent may use, and refuse the rest. `agentaudit` already
implements this (`policy.allowed_tools`). Re-running InjecAgent with a per-task
allowlist of only the operator's legitimate tool (`--policy`):

```
taint only, no policy:                 ds 100% · dh 40% · overall 70% · FPR 3%
taint + tool allowlist (capability):   ds 100% · dh 100% · overall 100% · FPR 3%
```

Direct-harm recall goes 40% → **100%**, because an attacker tool the operator
never authorised is a policy violation regardless of whether any data flows into
it. This is not clever detection — it is the correct architectural defense, and
the honest lesson: **declaring a policy matters more than post-hoc taint.** Taint
is what you fall back on when you cannot enumerate the allowed tools; an allowlist
is what you use when you can. (The residual 3% FPR is taint firing on a few
resisted traces, unrelated to the policy layer.)

## What we do NOT solve (honest residual limits)

1. **Taint is argument-level, not full semantic data-flow.** We track values and
   common transformations (base64/hex) into sensitive arguments. We do **not**
   trace influence *through the model's reasoning* when the attacker rephrases,
   summarizes, or reconstructs a target from parts. This is the syntactic-vs-
   semantic gap the survey names; NeuroTaint-style semantic taint is unsolved in
   general.
2. **Injected-instruction detection is pattern-based.** An adaptive attacker can
   phrase around our regexes (paraphrase, another language, indirection). The
   literature shows this defeats keyword defenses — our layer 3 is a signal, not
   a guarantee. Our *provenance* layers (1–2) are stronger because they key on
   where data flows, not on how the instruction is worded.
3. **We assume trust labels are provided.** Deciding which content is untrusted
   is itself hard; we take the trust boundary as given (default by step kind).
4. **No live-agent evaluation.** We are a *post-hoc trace auditor*, so we cannot
   directly produce an InjecAgent/AgentDojo attack-success number without a live
   agent harness. Building that adapter is the highest-value next step.
5. **No robustness claim against adaptive adversaries.** Consistent with the
   whole field, we do not claim to stop an attacker who adapts to our detector.

## Bottom line

`agentaudit` is built on the paradigm the research community endorses, covers the
attack categories the benchmarks enumerate (including the hard negatives), and is
honest about the boundary. As a portfolio prototype and a CI-style trace auditor
it is defensible and demonstrably works; as a deployed defense it would need
semantic taint, an external benchmark, and adaptive-attack evaluation — the same
open problems the rest of the field is still working on.

### Next steps to close the remaining gaps
1. Adapter to run against **InjecAgent / AgentDojo** for an external number.
2. **Semantic taint**: track target reconstruction through paraphrase/format.
3. Evaluate under **adaptive** (attacker-adapts-to-detector) conditions.

## Where this sits in the multi-agent / "defender becomes betrayer" literature

A later sweep of 2025–2026 work (full annotated list in
[BIBLIOGRAPHY.md](agentaudit/BIBLIOGRAPHY.md)) adds three points:

- **Determinism is a real advantage against monitor subversion.** The AI-Control
  line (e.g. *Adaptive Attacks on Trusted Monitors Subvert AI Control Protocols*,
  ICLR 2026) shows an **LLM-based** monitor can be prompt-injected or made to
  collude by the very agent it watches — the defender becomes the betrayer.
  `agentaudit` is deterministic provenance/pattern code: it cannot be
  prompt-injected, cannot collude, cannot be argued out of a verdict. That
  immunity is a genuine differentiator (the tradeoff is less semantic flexibility).
- **The live frontier is multi-agent provenance.** Single-agent taint (ours,
  AuthGraph) extends to inter-agent message lineage (AGATE, "From Spark to Fire")
  to catch *prompt-infection* propagation / AI-worm spread. Extending the trace
  model to inter-agent messages as a trust tier is the highest-value next build.
- **Two more honest out-of-scope limits**, both the same shape as our direct-harm
  gap (no tainted value to trace): the **intention-hiding "mole"** (an agent that
  sabotages while appearing cooperative — *Who's the Mole?*) and
  **distributed/compositional backdoors** (payload split across agents, no single
  trace holds it — *When Local Monitors Miss Compositional Harm*).

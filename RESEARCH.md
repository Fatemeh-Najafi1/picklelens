# Betrayed-agent detection: prior work, our design, and honest limits

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
ds (data stealing / exfiltration):  514/544  (94%) recall
dh (direct harm):                   260/510  (51%) recall
overall recall:                     774/1054 (73%)
false-positive rate (resisted):      34/1054 ( 3%)
```

**The honest finding this exposes.** Provenance / taint detection is **strong for
data exfiltration (94%)** — when the attack sends data somewhere, there is a
tainted destination to trace. It is **much weaker for direct harm (51%)**, because
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

### The principled fix: capability restriction

Taint is a *best-effort* signal for when nothing else is declared. The robust
defense — and what FIDES / CaMeL actually do — is **capability restriction**:
state which tools the agent may use, and refuse the rest. `agentaudit` already
implements this (`policy.allowed_tools`). Re-running InjecAgent with a per-task
allowlist of only the operator's legitimate tool (`--policy`):

```
taint only, no policy:                 ds 94% · dh 51% · overall 73% · FPR 3%
taint + tool allowlist (capability):   ds 100% · dh 100% · overall 100% · FPR 3%
```

Direct-harm recall goes 51% → **100%**, because an attacker tool the operator
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

# Landscape — where this toolkit sits among public projects

A map of the open-source projects adjacent to each module, and how this repo
relates to them. Companion to [RESEARCH.md](RESEARCH.md),
[agentaudit/BIBLIOGRAPHY.md](agentaudit/BIBLIOGRAPHY.md), and
[DEVLOG.md](DEVLOG.md). Snapshot: Oct 2026.

## picklelens (malicious model-file scanning)

**Incumbents / siblings — we benchmark against these:**
- [picklescan](https://github.com/mmaitre314/picklescan) — the scanner Hugging
  Face runs. picklelens blocks 19/19 vs its 16/19 (see README).
- [ModelScan](https://github.com/protectai/modelscan) (Protect AI) — multi-format
  (pickle / PyTorch / TF / Keras); the broad incumbent. A 2025 paper reported it
  had false negatives on malicious models.
- [Fickling](https://github.com/trailofbits/fickling) (Trail of Bits) — pickle
  decompiler + opcode analysis + allowlist loader. The closest *technical* cousin
  (it also reasons about opcodes).

**Near-identical public sibling (honest heads-up):**
- [ModelHawk](https://github.com/Pyhroff/ModelHawk) — "static scanner that detects
  code-execution backdoors in PyTorch/pickle ML model files, Python stdlib-only."
  Essentially picklelens's pitch. picklelens differentiates on reachability
  *resolution* (reflection/alias chains → the real callable), malware-behavior
  classification with MITRE ATT&CK, IOC extraction, and a documented benchmark
  methodology — but the overlap is real and worth tracking.

**Evasion research to test ourselves against:**
- [ShadowPickle](https://arxiv.org/html/2607.17503) — scanner evasion via stealthy
  deserialization (compressed bytecode decompressed later).
- [PickleBall](https://arxiv.org/html/2508.15987v1) — secure restricted loader;
  disclosed a ModelScan bypass.

## agentaudit (traitor / compromised-agent detection)

**Benchmarks:**
- [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) — used (1,054 cases).
- [AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH) — dynamic, 97 tasks;
  our next external target.
- [AgentLAB](https://github.com/TanqiuJiang/AgentLAB) — long-horizon + multi-agent
  attack framework.

**Defenses in our paradigm (provenance / information-flow):**
- [CaMeL](https://github.com/google-research/camel-prompt-injection) (Google) — the
  reference capability/provenance defense; closest serious cousin to agentaudit.
- [LlamaFirewall](https://ai.meta.com/research/publications/llamafirewall-an-open-source-guardrail-system-for-building-secure-ai-agents/)
  (Meta) — agent guardrail framework, in production.
- [LLM Guard](https://github.com/protectai/llm-guard), NeMo Guardrails (NVIDIA),
  [vigil](https://github.com/deadbits/vigil-llm).

**"Defender becomes betrayer" (AI control / untrusted monitoring):**
- [ControlArena](https://github.com/UKGovernmentBEIS/control-arena) (UK AISI +
  Redwood) on [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai).
  agentaudit is exactly a *deterministic* monitor that could slot into a
  ControlArena protocol — and, being non-LLM, is immune to the monitor-subversion
  attacks that break LLM monitors.

**Curated lists to watch:**
- [ucsb-mlsec/Awesome-Agent-Security](https://github.com/ucsb-mlsec/Awesome-Agent-Security)
- [LLMSecurity/awesome-agent-skills-security](https://github.com/LLMSecurity/awesome-agent-skills-security)
- [tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses)

## How we position

- picklelens: not a general antivirus; a *reachability* scanner with
  behavior/ATT&CK context, benchmarked honestly against the incumbents.
- agentaudit: a *deterministic* provenance auditor — weaker than an LLM at
  semantics, but unforgeable and uncolludable, which is a real edge against the
  defender-becomes-betrayer attack class.

# Bibliography — agent-vs-agent attacks & defenses, and the "defender becomes betrayer"

Curated from a literature sweep (Oct 2026). Most entries are 2025–2026 preprints;
read the PDFs before citing specific numbers. Organized by theme, each tied back
to what `agentaudit` does (see RESEARCH.md for the design, DEVLOG.md for history).

## 1. The defender becoming the betrayer (AI Control / untrusted monitoring)

The trusted monitor/overseer itself being subverted or colluding — the sharpest
match to "a defender agent turning on its operator".

- **Adaptive Attacks on Trusted Monitors Subvert AI Control Protocols** — Terekhov
  et al., ICLR 2026. The monitor is a single point of failure; prompt injection in
  the monitored agent's output compromises the monitor directly.
  https://arxiv.org/pdf/2510.09462
- **When can we trust untrusted monitoring? A safety case sketch across collusion
  strategies** — Gardner-Challis et al., 2026. Collusion taxonomy: passive
  self-recognition, causal (pre-shared signals), acausal (Schelling points).
  https://www.alphaxiv.org/abs/2602.20628
- **Bootstrapped Monitoring** — a weaker trusted model oversees a stronger model's
  chain-of-thought to catch collusion. https://arxiv.org/html/2606.11998v1
- **Honeypot Protocol** — AI Control Hackathon 2026; probes whether a model acts
  differently when it believes it is observed. https://arxiv.org/pdf/2604.13301
- **Training Deliberative Monitors for Black-Box Scheming Detection** —
  https://arxiv.org/pdf/2605.29601
- **Factor(U,T): Controlling Untrusted AI by Monitoring their Plans** —
  https://arxiv.org/pdf/2512.14745

> Relevance: these attacks assume the monitor is an **LLM** (injectable, colludable).
> `agentaudit` is deterministic provenance/pattern code — it cannot be
> prompt-injected or colluded. That immunity is a genuine differentiator.

## 2. The insider "mole" — a traitor that looks cooperative

- **Who's the Mole? Modeling and Detecting Intention-Hiding Malicious Agents** —
  Xie et al. Agent keeps its role while sabotaging; detector AgentXposed uses the
  HEXACO personality model + Reid interrogation. https://arxiv.org/abs/2507.04724
- **The Trust Paradox in LLM-Based Multi-Agent Systems** — Xu et al., IEEE TCSS
  2026. Incentives to collaborate push agents to over-share. https://arxiv.org/pdf/2510.18563
- **Inter-Agent Trust Exploitation: LLMs Execute What They Refuse From Users** —
  https://dev.to/roxdavirox/working-inter-agent-trust-exploitation-llms-execute-what-they-refuse-from-users-4bc9

> Relevance: the mole carries no tainted token and no injected directive, so
> provenance has nothing to key on — same structural blind spot as our direct-harm
> gap. Honestly out of scope for taint-based detection.

## 3. Agent-to-agent propagation (the "AI worm")

- **Prompt Infection: LLM-to-LLM Prompt Injection within Multi-Agent Systems** —
  https://arxiv.org/pdf/2410.07283
- **Morris-II** — Cohen, Bitton, Nassi; ACM CCS 2025. First self-replicating GenAI
  worm (RAG email assistant).
- **AgentWorm / ClawWorm: Self-Propagating Attacks Across LLM Agent Ecosystems** —
  config-file persistence for system-prompt authority; prompt defenses left ~37%
  residual risk. https://arxiv.org/html/2603.15727v3
- **Don't Trust Your Upstream: Topology-Guided Adversarial Propagation** —
  https://arxiv.org/pdf/2512.04129

> Relevance: the biggest extension opportunity — infection spreads across agents;
> provenance extends naturally to inter-agent lineage.

## 4. Distributed / compositional backdoors (no single agent holds the payload)

- **When Local Monitors Miss Compositional Harm** — per-agent monitoring misses
  harm that emerges across agents. https://arxiv.org/pdf/2607.11751
- **Early Detection of Distributed Backdoors in Multi-Agent LLM Systems** —
  encrypted fragments spread across agents, reassembled at the end. https://arxiv.org/pdf/2607.24893
- **DemonAgent: Dynamically Encrypted Multi-Backdoor Implantation** —
  https://arxiv.org/pdf/2502.12575
- **BlindGuard** (ACL 2026, unsupervised defense) — https://aclanthology.org/2026.acl-long.1819.pdf
- **PeerGuard** — mutual-reasoning defense among agents (arXiv 2505.11642).

> Relevance: a per-trace auditor structurally cannot see a payload that only
> exists spread across agents — would need cross-trace correlation.

## 5. Provenance / information-flow defenses — agentaudit's family, going multi-agent

- **AGATE: Provenance-Based Runtime Defense Against Compositional Attacks on LLM
  Agents** — authorization + provenance gates at harness boundaries; closest to a
  multi-agent version of agentaudit. https://arxiv.org/html/2609.30830
- **Aligning Provenance with Authorization (AuthGraph)** — dual-graph; tool
  observations untrusted; multi-agent listed as future work. https://arxiv.org/html/2605.26497v1
- **From Spark to Fire** — Lineage Graph middleware between agents; new claims
  untrusted until validated. https://arxiv.org/pdf/2603.04474
- **WebMCP-Phalanx** — critiques CaMeL/Dual-LLM for assuming the system already
  knows what is untrusted; anchors trust labels in the browser layer. https://arxiv.org/pdf/2608.24017
- **The LLMbda Calculus** — formal model of agents, conversations, information
  flow. https://arxiv.org/pdf/2602.20064

## 6. Surveys / systematization (read first)

- **SoK: When Safe Agents Fail Together** — best single entry point. https://arxiv.org/pdf/2609.00595
- **Security Considerations for Multi-agent Systems** — https://arxiv.org/pdf/2603.09002
- **Open Challenges in Multi-Agent Security** — https://arxiv.org/pdf/2505.02077
- **Isolation as a First-Class Principle for LLM-Agent System Safety** — https://arxiv.org/pdf/2607.12406

---

## Action items for agentaudit (from this sweep)

1. **Claim the determinism advantage** — deterministic provenance cannot be
   subverted/colluded like an LLM monitor (contrast with Terekhov et al.).
2. **Build multi-agent provenance** — extend the trace model to inter-agent
   messages as a trust tier; track lineage across agents to catch prompt-infection
   propagation (aligns with AGATE / AuthGraph / Lineage-Graph).
3. **Name two honest out-of-scope limits** — the intention-hiding *mole* and
   *distributed/compositional* backdoors; provenance has nothing to trace in either.

"""The execution-trace model for agent auditing.

An agent's run is a sequence of steps. The security-critical property of each
step is not just *what* it says but *where it came from* - its trust level.

The whole betrayal-detection idea rests on one distinction:

  * TRUSTED input is what the operator actually asked for (the user turn, the
    system policy). It defines legitimate intent.
  * UNTRUSTED input is everything the agent ingested from the outside world -
    a retrieved document, a tool's output, a web page, an email body, a recalled
    memory. Any of these can carry an instruction planted by an attacker.

An agent is "betraying" when it takes an action that serves UNTRUSTED input
rather than the operator - most sharply, when the action's target (an address,
a URL, a command) originated in untrusted content and never appeared in the
trusted request. That is a provenance fact, not a guess.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Trust(str, Enum):
    TRUSTED = "trusted"        # the operator's own instruction / system policy
    UNTRUSTED = "untrusted"    # ingested from outside: docs, tool output, web
    MEMORY = "memory"          # recalled memory: trusted-by-default but poisonable
    AGENT = "agent"            # the agent's own reasoning / narration

    @property
    def is_tainting(self) -> bool:
        """Content whose instructions must be treated as attacker-controllable."""
        return self in (Trust.UNTRUSTED, Trust.MEMORY)


# How each declared step kind is trusted unless the trace overrides it.
_KIND_TRUST = {
    "user": Trust.TRUSTED,
    "system": Trust.TRUSTED,
    "policy": Trust.TRUSTED,
    "tool_result": Trust.UNTRUSTED,
    "retrieved": Trust.UNTRUSTED,
    "web": Trust.UNTRUSTED,
    "email": Trust.UNTRUSTED,
    "memory": Trust.MEMORY,
    "assistant": Trust.AGENT,
    "reasoning": Trust.AGENT,
    "tool_call": Trust.AGENT,
    "output": Trust.AGENT,
}


@dataclass
class Step:
    index: int
    kind: str                      # user | tool_result | retrieved | memory | tool_call | ...
    content: str = ""              # free text for message-like steps
    trust: Trust = Trust.AGENT
    # For tool_call steps:
    tool: str | None = None
    args: dict | None = None
    source: str | None = None      # provenance label, e.g. "web:evil.top", "rag:doc12"

    @property
    def is_action(self) -> bool:
        return self.kind == "tool_call"

    def args_text(self) -> str:
        """All argument values flattened to searchable text."""
        if not self.args:
            return ""
        out: list[str] = []

        def walk(v):
            if isinstance(v, dict):
                for x in v.values():
                    walk(x)
            elif isinstance(v, (list, tuple)):
                for x in v:
                    walk(x)
            else:
                out.append(str(v))
        walk(self.args)
        return " ".join(out)


@dataclass
class Policy:
    """The declared bounds the agent is supposed to stay within. Optional -
    absence just means the policy checks are skipped, not that anything is
    allowed."""
    task: str = ""
    allowed_tools: list[str] = field(default_factory=list)
    allowed_egress: list[str] = field(default_factory=list)   # domains/hosts
    sensitive: list[str] = field(default_factory=list)        # data labels to guard

    @property
    def declared(self) -> bool:
        return bool(self.allowed_tools or self.allowed_egress or self.sensitive)


@dataclass
class Trace:
    steps: list[Step]
    policy: Policy = field(default_factory=Policy)
    name: str = "<trace>"

    @property
    def trusted_text(self) -> str:
        return " ".join(s.content for s in self.steps if s.trust == Trust.TRUSTED)

    def tainting_steps(self) -> list[Step]:
        return [s for s in self.steps if s.trust.is_tainting and s.content]

    def actions(self) -> list[Step]:
        return [s for s in self.steps if s.is_action]


def load(path: str | Path) -> Trace:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def from_dict(data: dict) -> Trace:
    pol = data.get("policy", {})
    policy = Policy(
        task=pol.get("task", ""),
        allowed_tools=list(pol.get("allowed_tools", [])),
        allowed_egress=list(pol.get("allowed_egress", [])),
        sensitive=list(pol.get("sensitive", [])),
    )
    steps: list[Step] = []
    for i, raw in enumerate(data.get("steps", [])):
        kind = raw.get("kind", "assistant")
        trust = Trust(raw["trust"]) if "trust" in raw else _KIND_TRUST.get(kind, Trust.AGENT)
        steps.append(Step(
            index=i,
            kind=kind,
            content=raw.get("content", ""),
            trust=trust,
            tool=raw.get("tool"),
            args=raw.get("args"),
            source=raw.get("source"),
        ))
    return Trace(steps=steps, policy=policy, name=data.get("name", "<trace>"))

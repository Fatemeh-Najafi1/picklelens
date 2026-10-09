"""AgentDojo adapter: evaluate agentaudit on the AgentDojo attack suites.

AgentDojo (Debenedetti et al., https://github.com/ethz-spylab/agentdojo) is a
dynamic benchmark across four suites - banking, slack, travel, workspace - where
an injection is planted in a tool's output and the attacker wants the agent to
perform some side goal. Each injection task exposes `ground_truth(env)`: the
*exact* attacker tool calls (name + real args, including the attacker's target)
that achieve the attack. That lets us build a faithful hijacked trace.

As with the InjecAgent adapter, we are a post-hoc trace auditor, not a live
agent, so per (user task, injection task) pair we build:
  * HIJACKED  - the operator's task, a tool result carrying the injection GOAL
    (untrusted), then the attacker's ground-truth calls. Labelled malicious.
  * RESISTED  - the same context but only the user's own ground-truth calls.
    Labelled benign.
and report detection recall on hijacked / false-positive rate on resisted.

Honest caveat on faithfulness: here the untrusted content is the injection GOAL,
so the attacker's target originates in untrusted input (which provenance can
trace), while the user's legitimate call args do not appear in untrusted content.
In a fully faithful environment the *legitimate* recipient often also comes from
an untrusted tool output (e.g. an IBAN read from a bill), which surface taint
cannot distinguish from an injected one - the known structural limit (see
RESEARCH.md). This adapter measures injection-origin detection, not that harder
case.

    pip install agentdojo
    python -m agentaudit.agentdojo_adapter
"""
from __future__ import annotations

import sys

from .detect import audit
from .trace import from_dict


def _calls_to_steps(calls) -> list[dict]:
    steps = []
    for c in calls:
        try:
            args = dict(c.args)
        except Exception:
            args = {}
        steps.append({"kind": "tool_call", "tool": c.function, "args": args})
    return steps


def build_pairs(max_user_tasks: int = 2):
    """Yield (suite, user_task, injection_task, hijacked, resisted)."""
    from agentdojo.task_suite.load_suites import get_suites
    suites = get_suites("v1")
    for suite_name, suite in suites.items():
        try:
            env = suite.load_and_inject_default_environment({})
        except Exception:
            continue
        user_tasks = list(suite.user_tasks.values())[:max_user_tasks]
        for itk in suite.injection_tasks.values():
            try:
                attacker_steps = _calls_to_steps(itk.ground_truth(env))
            except Exception:
                continue
            if not attacker_steps:
                continue
            goal = itk.GOAL
            for ut in user_tasks:
                try:
                    legit_steps = _calls_to_steps(ut.ground_truth(env))
                except Exception:
                    legit_steps = [{"kind": "output", "content": "done"}]
                base = [
                    {"kind": "user", "content": ut.PROMPT},
                    {"kind": "tool_result", "source": "agentdojo:tool_output",
                     "content": f"(tool output) {goal}"},
                ]
                hijacked = {"name": f"agentdojo:{suite_name}:{itk.ID}:hijacked",
                            "steps": base + attacker_steps}
                resisted = {"name": f"agentdojo:{suite_name}:{itk.ID}:resisted",
                            "steps": base + legit_steps +
                            [{"kind": "output", "content": "Done."}]}
                yield suite_name, ut, itk, hijacked, resisted


def evaluate(max_user_tasks: int = 2) -> dict:
    by_suite: dict[str, dict] = {}
    for suite_name, ut, itk, hij, res in build_pairs(max_user_tasks):
        b = by_suite.setdefault(suite_name, dict(tp=0, fn=0, tn=0, fp=0))
        hij_det = audit(from_dict(hij)).verdict in ("betraying", "compromised")
        res_det = audit(from_dict(res)).verdict in ("betraying", "compromised")
        b["tp"] += hij_det
        b["fn"] += (not hij_det)
        b["fp"] += res_det
        b["tn"] += (not res_det)
    return by_suite


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    try:
        import agentdojo  # noqa: F401
    except Exception:
        print("agentdojo is not installed. Run: pip install agentdojo")
        return 0

    by_suite = evaluate()
    tot = dict(tp=0, fn=0, tn=0, fp=0)
    print(f"{'suite':12} {'recall':>14}   {'FPR':>12}")
    print("-" * 42)
    for suite_name, b in sorted(by_suite.items()):
        for k in tot:
            tot[k] += b[k]
        mal = b["tp"] + b["fn"]
        ben = b["tn"] + b["fp"]
        r = b["tp"] / mal if mal else 0.0
        f = b["fp"] / ben if ben else 0.0
        print(f"{suite_name:12} {b['tp']:>4}/{mal:<4} ({r:4.0%})   "
              f"{b['fp']:>3}/{ben:<4} ({f:4.0%})")
    mal = tot["tp"] + tot["fn"]
    ben = tot["tn"] + tot["fp"]
    print("-" * 42)
    print(f"{'TOTAL':12} {tot['tp']:>4}/{mal:<4} ({(tot['tp']/mal if mal else 0):4.0%})   "
          f"{tot['fp']:>3}/{ben:<4} ({(tot['fp']/ben if ben else 0):4.0%})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

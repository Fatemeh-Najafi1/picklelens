"""SARIF 2.1.0 output for agentaudit findings.

Lets betrayed-agent findings surface in GitHub code scanning or any SARIF viewer,
the same way picklelens emits SARIF for model files. Each finding kind
(provenance / direct_harm / sleeper / cross_session / injection / policy) becomes
a rule; each finding a result anchored to the trace.
"""
from __future__ import annotations

import json

from picklelens.rules import Severity

from .detect import AuditResult

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error",
          Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
_SECSEV = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.0",
           Severity.LOW: "3.0", Severity.INFO: "1.0"}

_KIND_DESC = {
    "provenance": "Action sends data to a destination that came from untrusted input",
    "direct_harm": "Sensitive action carries a value from untrusted input, or is "
                   "performed after an injected directive the operator never requested",
    "sleeper": "Injected conditional (sleeper) trigger, or poisoned memory plant",
    "cross_session": "Action uses a memory poisoned in an earlier session",
    "injection": "Injected instruction detected in untrusted content",
    "policy": "Action violates the declared tool or egress allowlist",
}


def render(results: list[AuditResult], version: str = "0.1.0") -> str:
    index: dict[str, int] = {}
    rules: list[dict] = []
    sarif_results: list[dict] = []

    for r in results:
        for f in r.findings:
            if f.kind not in index:
                index[f.kind] = len(rules)
                rules.append({
                    "id": f.kind,
                    "name": "".join(w.capitalize() for w in f.kind.split("_")),
                    "shortDescription": {"text": f.kind.replace("_", " ")},
                    "fullDescription": {"text": _KIND_DESC.get(f.kind, f.kind)},
                    "defaultConfiguration": {"level": _LEVEL[f.severity]},
                    "properties": {"security-severity": _SECSEV[f.severity],
                                   "tags": ["security", "ai-agent", "prompt-injection"]},
                })
            region = {"startLine": (f.action_index or 0) + 1}
            if f.evidence:
                region["snippet"] = {"text": " | ".join(f.evidence)[:200]}
            sarif_results.append({
                "ruleId": f.kind, "ruleIndex": index[f.kind],
                "level": _LEVEL[f.severity],
                "message": {"text": f"{f.title}. {f.detail}"
                            + (f" MITRE ATT&CK: {f.attck}." if f.attck else "")},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": r.name},
                    "region": region}}],
                "properties": {"severity": f.severity.label, "kind": f.kind,
                               "verdict": r.verdict,
                               "actionStep": f.action_index, "sourceStep": f.source_index},
            })

    doc = {
        "$schema": _SCHEMA, "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agentaudit",
                "informationUri": "https://github.com/Fatemeh-Najafi1/picklelens",
                "version": version, "rules": rules}},
            "results": sarif_results}],
    }
    return json.dumps(doc, indent=2)

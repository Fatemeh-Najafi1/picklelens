"""SARIF 2.1.0 output for GitHub code scanning.

Emitting SARIF lets picklelens findings appear natively in a repository's
Security tab (and in PR "Files changed" annotations) when run via
`github/codeql-action/upload-sarif`. Each distinct sink category becomes a
rule; each finding becomes a result anchored to the offending file.
"""
from __future__ import annotations

import json

from .rules import Severity
from .scanner import ScanResult

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF only defines error/warning/note; map our severities onto them and keep
# the precise level in a property for anyone who wants it.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub renders security-severity (0-10) as critical/high/medium/low.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5", Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0", Severity.LOW: "3.0", Severity.INFO: "1.0",
}


def _rules(results: list[ScanResult]) -> tuple[list[dict], dict[str, int]]:
    index: dict[str, int] = {}
    rules: list[dict] = []
    for r in results:
        for f in r.findings:
            if f.category in index:
                continue
            index[f.category] = len(rules)
            rules.append({
                "id": f.category,
                "name": "".join(w.capitalize() for w in f.category.split("_")),
                "shortDescription": {"text": f.category.replace("_", " ")},
                "fullDescription": {"text":
                    f"Reachable {f.category.replace('_', ' ')} in a "
                    f"pickle/model file, detected by symbolic reachability "
                    f"analysis of the opcode stream."},
                "defaultConfiguration": {"level": _LEVEL[f.severity]},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                    "tags": ["security", "ml-supply-chain"],
                },
            })
    return rules, index


def render(results: list[ScanResult], version: str = "0.1.0") -> str:
    rules, index = _rules(results)
    sarif_results: list[dict] = []

    for r in results:
        for f in r.findings:
            profile = r.profile or ""
            attck = ", ".join(sorted({b.attck for b in r.behaviors})) if r.behaviors else ""
            msg = f"{'Calls' if f.reachable else 'References'} {f.qualname}: {f.note}."
            if profile:
                msg += f" File behavior profile: {profile}."
            if attck:
                msg += f" MITRE ATT&CK: {attck}."
            sarif_results.append({
                "ruleId": f.category,
                "ruleIndex": index[f.category],
                "level": _LEVEL[f.severity],
                "message": {"text": msg},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _uri(r.path)},
                        # Offsets are within the (possibly embedded) stream, so
                        # we surface them as a region on the file for context.
                        "region": {"startLine": 1,
                                   "snippet": {"text": f.evidence[:200]}},
                    },
                }],
                "properties": {
                    "severity": f.severity.label,
                    "stream": f.stream,
                    "byteOffset": f.position,
                    "reachable": f.reachable,
                    "riskScore": r.risk,
                },
            })

    doc = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "picklelens",
                "informationUri": "https://github.com/Fatemeh-Najafi1/picklelens",
                "version": version,
                "rules": rules,
            }},
            "results": sarif_results,
        }],
    }
    return json.dumps(doc, indent=2)


def _uri(path: str) -> str:
    return path.replace("\\", "/")

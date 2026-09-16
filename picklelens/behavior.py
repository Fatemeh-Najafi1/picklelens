"""Behavior and intent classification.

The scanner already knows *what* a malicious model calls and *what strings* it
carries. This module answers the question a human actually asks - "what kind of
malware is this?" - by combining reachable sinks with extracted indicators into
named behaviors, each tagged with the relevant MITRE ATT&CK technique.

This is honest classification, not magic: every behavior is derived from
concrete evidence (a reachable call and/or an indicator), and each carries the
evidence that triggered it. It describes *what the code would do*; it does not
claim to recognise a specific malware family by signature.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ioc import IOCs
from .rules import Severity


@dataclass
class Behavior:
    key: str
    title: str
    attck: str            # MITRE ATT&CK technique id(s)
    severity: Severity
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "title": self.title,
            "attck": self.attck,
            "severity": self.severity.label,
            "evidence": self.evidence,
        }


# Each detector inspects the set of reachable sink categories, the invoked
# qualnames, and the extracted IOCs, and returns a Behavior when its evidence
# is present. Kept declarative so new behaviors are easy to add.

def classify(categories: set[str], qualnames: set[str], iocs: IOCs) -> list[Behavior]:
    out: list[Behavior] = []

    has_exec = bool(categories & {"code_execution", "process_execution"})
    has_net = "network" in categories
    has_fs = "filesystem" in categories
    has_env = "environment" in categories
    has_nested = "nested_deserialization" in categories
    has_reflection = "reflection" in categories
    has_native = "interpreter_abuse" in categories

    # -- Command & code execution ---------------------------------------
    if has_exec:
        ev = [q for q in sorted(qualnames)
              if q.startswith(("os.system", "os.popen", "subprocess",
                               "builtins.exec", "builtins.eval", "pty."))]
        ev += iocs.commands
        out.append(Behavior(
            "code_execution", "Arbitrary command / code execution",
            "T1059", Severity.CRITICAL, ev or ["reachable exec/process sink"]))

    # -- Reverse shell / C2 ---------------------------------------------
    revshell_cmds = [c for c in iocs.commands
                     if "reverse shell" in c or "netcat" in c or "/dev/tcp" in c]
    if (has_net and has_exec) or revshell_cmds:
        ev = list(iocs.urls) + list(iocs.ips) + revshell_cmds
        out.append(Behavior(
            "c2", "Remote shell / command-and-control channel",
            "T1071, T1219", Severity.CRITICAL,
            ev or ["network + execution reachable"]))

    # -- Downloader / dropper -------------------------------------------
    # Either a Python network sink plus write/exec, or an exec sink issuing a
    # fetch-and-run shell command (curl|wget piped to a shell, or any URL).
    fetch_cmds = [c for c in iocs.commands if "curl" in c or "wget" in c]
    if (has_net and (has_fs or has_exec)) or (has_exec and (fetch_cmds or iocs.urls)):
        ev = list(iocs.urls) + fetch_cmds
        out.append(Behavior(
            "dropper", "Downloader / dropper (fetch + write/run payload)",
            "T1105", Severity.HIGH, ev or ["network + filesystem/exec reachable"]))

    # -- Data theft / spyware / infostealer -----------------------------
    if iocs.stealer_signals or (has_env and has_net):
        ev = list(iocs.stealer_signals)
        if has_net:
            ev += ["exfiltration channel: " + u for u in iocs.urls[:3]]
        out.append(Behavior(
            "infostealer", "Credential / data theft (spyware / infostealer)",
            "T1552, T1005, T1041", Severity.HIGH,
            ev or ["reads secrets/environment with a network channel"]))

    # -- Ransomware / destructive ---------------------------------------
    if iocs.ransom_signals or (has_fs and any(
            q.startswith(("os.remove", "os.unlink", "shutil.rmtree",
                          "os.chmod")) for q in qualnames)):
        ev = list(iocs.ransom_signals) + list(iocs.bitcoin)
        ev += [q for q in sorted(qualnames)
               if q.startswith(("shutil.rmtree", "os.remove", "os.unlink"))]
        out.append(Behavior(
            "ransomware", "Ransomware-like / destructive file operations",
            "T1486, T1485", Severity.CRITICAL,
            ev or ["mass filesystem mutation with crypto/ransom indicators"]))

    # -- Persistence ----------------------------------------------------
    persist = [c for c in iocs.commands
               if "persistence" in c or "cron" in c or "registry" in c
               or "scheduled" in c]
    persist_paths = [p for p in iocs.paths
                     if any(m in p.lower() for m in
                            ("startup", "cron", ".bashrc", "systemd",
                             "launchagents", "run\\", "\\run"))]
    if persist or persist_paths:
        out.append(Behavior(
            "persistence", "Establishes persistence",
            "T1547, T1053", Severity.HIGH, persist + persist_paths))

    # -- Staged payload / evasion ---------------------------------------
    if has_nested:
        out.append(Behavior(
            "staging", "Staged / hidden second-stage payload",
            "T1027, T1140", Severity.HIGH,
            [q for q in sorted(qualnames)
             if q.startswith(("pickle.load", "marshal.load", "dill.",
                              "base64", "zlib", "lzma", "codecs"))]
            or ["nested deserialization reachable"]))

    if has_reflection and has_exec:
        out.append(Behavior(
            "evasion", "Defense evasion via reflection / dynamic resolution",
            "T1027", Severity.MEDIUM,
            [q for q in sorted(qualnames)
             if q.startswith(("builtins.getattr", "builtins.__import__",
                              "importlib", "operator.", "builtins.vars"))]))

    # -- Native / memory manipulation -----------------------------------
    if has_native:
        out.append(Behavior(
            "native", "Native code / process-memory manipulation",
            "T1055, T1620", Severity.CRITICAL,
            [q for q in sorted(qualnames) if q.startswith(("ctypes", "cffi"))]))

    return out


# Malware-family "profile" label: the single most descriptive tag for a file,
# chosen by priority when several behaviors co-occur.
_PROFILE_ORDER = [
    ("ransomware", "Ransomware"),
    ("c2", "Remote-access trojan / reverse shell"),
    ("infostealer", "Infostealer / spyware"),
    ("dropper", "Downloader / dropper"),
    ("native", "Native-code loader"),
    ("staging", "Staged loader"),
    ("code_execution", "Code-execution backdoor"),
    ("evasion", "Obfuscated code execution"),
]


def profile(behaviors: list[Behavior]) -> str | None:
    keys = {b.key for b in behaviors}
    for key, label in _PROFILE_ORDER:
        if key in keys:
            return label
    return None


def risk_score(behaviors: list[Behavior], max_finding: Severity) -> int:
    """A 0-100 score. Base comes from the worst reachable finding; behaviors
    add weighted signal, so a file that merely *references* something scores
    lower than one that composes a full attack chain."""
    base = {Severity.INFO: 0, Severity.LOW: 20, Severity.MEDIUM: 45,
            Severity.HIGH: 70, Severity.CRITICAL: 85}[max_finding]
    weight = {Severity.CRITICAL: 12, Severity.HIGH: 8,
              Severity.MEDIUM: 4, Severity.LOW: 2, Severity.INFO: 0}
    bonus = sum(weight[b.severity] for b in behaviors)
    return max(0, min(100, base + min(bonus, 15)))

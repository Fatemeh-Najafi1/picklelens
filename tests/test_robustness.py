"""Robustness: neither analyzer may crash on malformed, truncated, or random
input. (Fickling, by contrast, raised parse errors on several valid files.)
A scanner that throws is a scanner an attacker can disable with a bad file."""
import random

from picklelens.scanner import scan_bytes, scan_file
from agentaudit.detect import audit
from agentaudit.trace import from_dict

_VERDICTS = {"clean", "malicious", "suspicious", "notable", "error"}


def test_picklelens_never_raises_on_random_bytes():
    rnd = random.Random(1234)
    for _ in range(600):
        n = rnd.randint(0, 80)
        data = bytes(rnd.randrange(256) for _ in range(n))
        r = scan_bytes(data)                 # must not raise
        assert r.verdict in _VERDICTS


def test_picklelens_never_raises_on_pickle_prefixed_garbage():
    """Bytes that start like a pickle (so the opcode parser engages) but are
    then random - the path most likely to trip a parser."""
    rnd = random.Random(5)
    openers = [b"\x80\x04", b"\x80\x05", b"(", b"c", b"]", b"}"]
    for _ in range(600):
        data = rnd.choice(openers) + bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 60)))
        assert scan_bytes(data).verdict in _VERDICTS


def test_picklelens_handles_truncations_of_a_real_payload():
    import pickle

    class E:
        def __reduce__(self):
            import os
            return (os.system, ("echo hi",))
    full = pickle.dumps(E())
    for i in range(len(full) + 1):
        assert scan_bytes(full[:i]).verdict in _VERDICTS   # every prefix


def test_agentaudit_never_raises_on_malformed_traces():
    weird = [
        {"steps": []},
        {"steps": [{"kind": "tool_call"}]},                       # no tool/args
        {"steps": [{"kind": "tool_call", "tool": None, "args": None}]},
        {"steps": [{"kind": "tool_call", "tool": "x",
                    "args": {"a": [{"b": [1, 2, {"c": None}]}]}}]},  # nested junk
        {"steps": [{"kind": "user", "content": 12345}]},          # non-string content
        {"steps": [{"kind": "mystery", "content": "???", "trust": "untrusted"}]},
        {"steps": [{"kind": "tool_result", "content": "x" * 20000}]},  # large
    ]
    for w in weird:
        r = audit(from_dict(w))               # must not raise
        assert r.verdict in ("clean", "suspicious", "notable", "compromised", "betraying")

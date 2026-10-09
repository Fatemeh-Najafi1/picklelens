"""Detection benchmark: every in-scope malicious sample must be flagged,
every benign sample must stay clean, and the out-of-scope sample documents
the stated limitation rather than counting against detection.
"""
import json
from pathlib import Path

import pytest

from picklelens.scanner import scan_bytes, scan_file
from tests import make_samples

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


@pytest.fixture(scope="session", autouse=True)
def _build_samples():
    make_samples.build()


def _manifest():
    return json.loads((SAMPLES / "manifest.json").read_text())


def _cases():
    return [(e["name"], e["malicious"], e["family"], e["in_scope"])
            for e in _manifest()]


@pytest.mark.parametrize("name,malicious,family,in_scope", _cases())
def test_sample(name, malicious, family, in_scope):
    res = scan_file(SAMPLES / name)
    flagged = res.verdict in ("malicious", "suspicious")
    if not in_scope:
        # Documented limitation: malice lives in installed class code, not the
        # stream. We assert the tool does NOT hallucinate a stream finding.
        assert not flagged, f"{name} should be out of scope for stream analysis"
        return
    if malicious:
        assert flagged, f"MISS: {name} ({family}) not flagged; verdict={res.verdict}"
    else:
        assert not flagged, f"FALSE ALARM: {name} flagged as {res.verdict}"


def test_clean_verdict_has_no_findings():
    res = scan_file(SAMPLES / "benign_dict.pkl")
    assert res.verdict == "clean"
    assert res.findings == []


def test_alias_normalised_to_os_system():
    res = scan_file(SAMPLES / "mal_alias.pkl")
    assert any(f.qualname == "os.system" for f in res.findings), \
        "posix.system alias should normalise to os.system"


def test_getattr_dynamic_import_resolves_to_os_system():
    """getattr(__import__('os'), 'system') must resolve to os.system, not just
    surface the intermediate __import__ reference."""
    res = scan_file(SAMPLES / "mal_getattr.pkl")
    assert res.verdict == "malicious"
    assert any(f.qualname == "os.system" and f.reachable for f in res.findings)


def test_stack_global_is_caught():
    res = scan_file(SAMPLES / "mal_stackglobal.pkl")
    assert res.verdict == "malicious"
    assert any(f.qualname == "os.system" for f in res.findings)


def test_reachable_ranks_above_reference():
    """An invoked sink must outrank a merely-referenced one of the same kind."""
    res = scan_file(SAMPLES / "mal_direct.pkl")
    top = res.findings[0]
    assert top.reachable is True
    assert top.severity.label == "critical"


def test_malformed_stream_does_not_crash():
    res = scan_bytes(b"\x80\x04\x95\xff\xff\xff\xff", path="junk")
    # Truncated/garbage input yields an error, never an exception.
    assert res.verdict in ("error", "clean")


def test_truncated_is_reported_not_raised():
    res = scan_bytes(b"c", path="one-byte")
    assert res.streams[0].error is not None or res.verdict == "clean"


# -- narrowed "honest limits": __setstate__, PERSID, extensions -----------

def test_unvetted_setstate_class_is_flagged_for_review():
    """An object of an unrecognized class reconstructed via BUILD (its
    __setstate__ runs on load) is now surfaced as a low 'review' finding, not
    cleared - even though the class code is external to the pickle."""
    r = scan_file(SAMPLES / "oos_classsetstate.pkl")
    assert r.verdict == "notable"            # was 'clean' before
    assert any(f.category == "unvetted_state" for f in r.findings)


def test_vetted_class_state_is_not_flagged():
    from picklelens.scanner import scan_bytes
    import pickle, collections
    r = scan_bytes(pickle.dumps(collections.OrderedDict(a=1, b=2)))
    assert r.verdict == "clean"


def test_persistent_id_is_surfaced():
    import io, pickle
    from picklelens.scanner import scan_bytes

    class P(pickle.Pickler):
        def persistent_id(self, obj):
            return "ref" if isinstance(obj, set) else None
    buf = io.BytesIO()
    P(buf).dump({"x": {1, 2, 3}})
    r = scan_bytes(buf.getvalue())
    assert any(f.category == "opaque_persid" for f in r.findings)


def test_unknown_extension_code_is_surfaced():
    from picklelens.scanner import scan_bytes
    data = b"\x80\x02\x82\xff."            # PROTO 2, EXT1 code 255 (unregistered), STOP
    r = scan_bytes(data)
    assert any(f.category == "opaque_extension" for f in r.findings)

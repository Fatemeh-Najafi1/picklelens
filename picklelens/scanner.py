"""File-level scanning: container handling, findings, and verdicts.

Model files are rarely a bare pickle. A PyTorch `.pt` is a ZIP archive with a
`data.pkl` member inside it; a `.npz` is a ZIP of `.npy` members, each of which
may carry an embedded pickle. We locate every pickle stream in a file and run
the machine over each one. Nothing is ever extracted to disk or deserialised.
"""
from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import TYPE_CHECKING

from .machine import Machine, Trace
from .rules import Severity, classify, downgrade, normalize
from .symbolic import Const, Global, Sym

if TYPE_CHECKING:
    from .behavior import Behavior
    from .ioc import IOCs

# Guards against decompression bombs in ZIP-based model containers.
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 10_000

SAFETENSORS_MAGIC_MAX_HEADER = 100 * 1024 * 1024


@dataclass
class Finding:
    severity: Severity
    category: str
    qualname: str
    note: str
    reachable: bool          # True = the program calls it, False = names only
    via: str                 # reduce / newobj / build / reference
    position: int            # byte offset within the pickle stream
    stream: str              # which member of the container
    evidence: str            # rendered call, e.g. os.system('curl ...')

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


@dataclass
class StreamResult:
    name: str
    protocol: int
    opcode_count: int
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    truncated: bool = False
    opaque: list[tuple[str, int]] = field(default_factory=list)
    literals: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    path: str
    format: str
    streams: list[StreamResult] = field(default_factory=list)
    error: str | None = None

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for s in self.streams:
            out.extend(s.findings)
        return out

    @property
    def severity(self) -> Severity:
        f = self.findings
        return max((x.severity for x in f), default=Severity.INFO)

    @property
    def literals(self) -> list[str]:
        out: list[str] = []
        for s in self.streams:
            out.extend(s.literals)
        return out

    @property
    def iocs(self) -> "IOCs":
        from .ioc import extract
        return extract(self.literals)

    @property
    def behaviors(self) -> "list[Behavior]":
        from .behavior import classify
        cats = {f.category for f in self.findings if f.reachable}
        quals = {f.qualname for f in self.findings if f.reachable}
        return classify(cats, quals, self.iocs)

    @property
    def profile(self) -> "str | None":
        from .behavior import profile
        return profile(self.behaviors)

    @property
    def risk(self) -> int:
        from .behavior import risk_score
        return risk_score(self.behaviors, self.severity)

    @property
    def verdict(self) -> str:
        if self.error:
            return "error"
        if not self.findings:
            return "clean"
        sev = self.severity
        if sev >= Severity.HIGH:
            return "malicious"
        if sev >= Severity.MEDIUM:
            return "suspicious"
        return "notable"

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "format": self.format,
            "verdict": self.verdict,
            "severity": self.severity.label,
            "risk": self.risk,
            "profile": self.profile,
            "behaviors": [b.to_dict() for b in self.behaviors],
            "iocs": self.iocs.to_dict(),
            "error": self.error,
            "streams": [
                {
                    "name": s.name,
                    "protocol": s.protocol,
                    "opcodes": s.opcode_count,
                    "error": s.error,
                    "truncated": s.truncated,
                    "findings": [f.to_dict() for f in s.findings],
                }
                for s in self.streams
            ],
        }


def _render(sym: Sym, args: tuple[Sym, ...] | None) -> str:
    base = sym.describe()
    if args is None:
        return base
    # When the callable was recovered through a reflection/alias chain
    # (getattr, __import__, import_module), the recorded args belong to that
    # plumbing, not to the resolved target - showing them is misleading. Print
    # the real callable with an elided argument list instead.
    if isinstance(sym, Global) and sym.dynamic:
        return f"{base}(...)"
    rendered = []
    for a in args:
        text = a.describe()
        if len(text) > 80:
            text = text[:77] + "..."
        rendered.append(text)
    return f"{base}({', '.join(rendered)})"


def analyze_stream(data: bytes, name: str, machine: Machine | None = None) -> StreamResult:
    """Run the machine over one pickle stream and grade what it found."""
    machine = machine or Machine()
    trace: Trace = machine.run(data)
    result = StreamResult(
        name=name,
        protocol=trace.protocol,
        opcode_count=trace.opcode_count,
        error=trace.error,
        truncated=trace.truncated,
        opaque=trace.opaque,
        literals=[s for s, _ in trace.literals],
    )

    invoked: set[str] = set()
    for inv in trace.invocations:
        qual = inv.qualname
        invoked.add(normalize(qual))
        sink = classify(qual)
        if sink is None:
            continue
        result.findings.append(
            Finding(
                severity=sink.severity,
                category=sink.category,
                qualname=normalize(qual),
                note=sink.note,
                reachable=True,
                via=inv.via,
                position=inv.position,
                stream=name,
                evidence=_render(inv.target, inv.args),
            )
        )

    # Globals that were named but never invoked. Real signal, lower weight.
    for g, pos in trace.globals_referenced:
        qual = normalize(g.qualname)
        if qual in invoked:
            continue
        sink = classify(g.qualname)
        if sink is None:
            continue
        result.findings.append(
            Finding(
                severity=downgrade(sink.severity),
                category=sink.category,
                qualname=qual,
                note=f"{sink.note} (referenced, not invoked in this stream)",
                reachable=False,
                via="reference",
                position=pos,
                stream=name,
                evidence=g.qualname,
            )
        )

    result.findings.sort(key=lambda f: (-f.severity, f.position))
    return result


# --- container handling -------------------------------------------------

PICKLE_SUFFIXES = {".pkl", ".pickle", ".bin", ".ckpt", ".pt", ".pth", ".model", ".data"}


def _looks_like_pickle(data: bytes) -> bool:
    if not data:
        return False
    # Protocol 2+ starts with the PROTO opcode; protocol 0/1 start with an
    # ordinary opcode character. We accept the common openers.
    return data[:1] in (b"\x80", b"(", b"]", b"}", b"c", b"S", b"V", b"I", b"K", b"N")


def scan_bytes(data: bytes, path: str = "<bytes>", label: str = "stream") -> ScanResult:
    return ScanResult(path=path, format="pickle", streams=[analyze_stream(data, label)])


_HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
_7Z_MAGIC = b"7z\xbc\xaf\x27\x1c"


def scan_file(path: str | Path) -> ScanResult:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        return ScanResult(path=str(p), format="unknown", error=str(exc))

    if p.suffix == ".safetensors":
        return _scan_safetensors(p, raw)
    if raw[:8] == _HDF5_MAGIC or p.suffix in (".h5", ".hdf5"):
        return _scan_hdf5(p, raw)
    if raw[:6] == _7Z_MAGIC:
        return _scan_7z(p, raw)
    if zipfile.is_zipfile(io.BytesIO(raw)):
        return _scan_zip(p, raw)
    if raw[:6] == b"\x93NUMPY":
        return _scan_npy(p, raw)
    if _looks_like_pickle(raw):
        return ScanResult(path=str(p), format="pickle",
                          streams=[analyze_stream(raw, p.name)])

    return ScanResult(path=str(p), format="unrecognized",
                      error="not a pickle, model archive, HDF5, or safetensors file")


# --- Keras Lambda-layer detection --------------------------------------
# Keras models (.keras = ZIP with config.json; .h5 = HDF5 with a model_config
# JSON attribute) may contain Lambda layers. A Lambda layer serializes a Python
# function - as a base64-encoded marshalled code object - that Keras executes
# with `python_utils.func_load` on model load. Loading such a model is
# arbitrary code execution, independent of any pickle. (CVE-2024-3660 class.)

def _keras_findings(config_text: str, stream: str) -> list[Finding]:
    findings: list[Finding] = []
    lower = config_text.lower()
    if '"lambda"' not in lower and "'lambda'" not in lower:
        return findings

    # Count Lambda layers and whether a serialized function payload is present.
    n_lambda = lower.count('"class_name": "lambda"') + lower.count('"class_name":"lambda"')
    has_fn = '"function"' in lower or "'function'" in lower
    findings.append(Finding(
        severity=Severity.CRITICAL if has_fn else Severity.HIGH,
        category="code_execution",
        qualname="keras.Lambda",
        note=("Keras Lambda layer executes an embedded Python function on "
              "model load (func_load of a marshalled code object)"),
        reachable=has_fn,
        via="keras_lambda",
        position=lower.find("lambda"),
        stream=stream,
        evidence=f"{max(n_lambda, 1)} Lambda layer(s) with embedded function"
                 if has_fn else "Lambda layer present",
    ))
    return findings


def _scan_hdf5(p: Path, raw: bytes) -> ScanResult:
    """Best-effort .h5 scan.

    We prefer h5py when available (to read the model_config attribute cleanly);
    otherwise we byte-scan for the embedded model_config JSON. Either way we are
    only reading metadata - never loading the model.
    """
    result = ScanResult(path=str(p), format="keras-hdf5")
    config_text = ""
    try:
        import h5py  # type: ignore
        import io as _io
        with h5py.File(_io.BytesIO(raw), "r") as f:
            mc = f.attrs.get("model_config")
            if isinstance(mc, bytes):
                mc = mc.decode("utf-8", "replace")
            config_text = mc or ""
    except Exception:
        # Fall back to scanning the raw bytes for the JSON model_config blob.
        text = raw.decode("latin-1", "replace")
        idx = text.find("model_config")
        window = text[idx:idx + 200_000] if idx >= 0 else text
        config_text = window

    findings = _keras_findings(config_text, p.name)
    sr = StreamResult(name=p.name, protocol=0, opcode_count=0)
    sr.findings = findings
    sr.literals = [config_text[:8192]] if findings else []
    result.streams.append(sr)
    if not findings:
        result.format = "keras-hdf5 (no Lambda layers)"
    return result


def _scan_zip(p: Path, raw: bytes) -> ScanResult:
    """PyTorch .pt/.pth and .npz are ZIP archives containing pickle members."""
    result = ScanResult(path=str(p), format="zip-archive")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            members = zf.infolist()[:MAX_MEMBERS]
            for info in members:
                if info.is_dir() or info.file_size > MAX_MEMBER_BYTES:
                    continue
                suffix = Path(info.filename).suffix
                if suffix not in PICKLE_SUFFIXES and suffix != ".npy":
                    continue
                try:
                    member = zf.read(info)
                except Exception as exc:
                    result.streams.append(
                        StreamResult(name=info.filename, protocol=0,
                                     opcode_count=0, error=str(exc))
                    )
                    continue
                if suffix == ".npy":
                    embedded = _npy_payload(member)
                    if embedded is None:
                        continue
                    member = embedded
                if not _looks_like_pickle(member):
                    continue
                result.streams.append(analyze_stream(member, info.filename))

            # A .keras archive carries a config.json that may hold Lambda
            # layers - a code-execution vector independent of any pickle.
            for info in members:
                base = Path(info.filename).name
                if base not in ("config.json", "metadata.json", "model.json"):
                    continue
                if info.file_size > MAX_MEMBER_BYTES:
                    continue
                try:
                    text = zf.read(info).decode("utf-8", "replace")
                except Exception:
                    continue
                findings = _keras_findings(text, info.filename)
                if findings:
                    sr = StreamResult(name=info.filename, protocol=0,
                                      opcode_count=0)
                    sr.findings = findings
                    sr.literals = [text[:8192]]
                    result.streams.append(sr)
                    result.format = "keras-archive"
    except zipfile.BadZipFile as exc:
        result.error = f"corrupt archive: {exc}"

    if not result.streams and not result.error:
        result.format = "zip-archive (no pickle members)"
    return result


def _scan_7z(p: Path, raw: bytes) -> ScanResult:
    """7z model archives need py7zr to extract; inspect members if available.

    Without py7zr we cannot decompress, so we report the format plainly rather
    than failing - the file is still flagged as an opaque container to review.
    """
    result = ScanResult(path=str(p), format="7z-archive")
    try:
        import py7zr  # type: ignore
    except Exception:
        result.error = ("7z archive - install 'py7zr' to inspect its members "
                        "(cannot decompress without it)")
        return result
    try:
        import io as _io
        with py7zr.SevenZipFile(_io.BytesIO(raw), "r") as z:
            for name, bio in (z.readall() or {}).items():
                suffix = Path(name).suffix
                if suffix not in PICKLE_SUFFIXES and suffix != ".npy":
                    continue
                member = bio.read()
                if len(member) > MAX_MEMBER_BYTES:
                    continue
                if suffix == ".npy":
                    emb = _npy_payload(member)
                    if emb is None:
                        continue
                    member = emb
                if _looks_like_pickle(member):
                    result.streams.append(analyze_stream(member, name))
    except Exception as exc:
        result.error = f"could not read 7z archive: {exc}"
    return result


def _npy_payload(raw: bytes) -> bytes | None:
    """Return the embedded pickle of an object-dtype .npy, if there is one."""
    if raw[:6] != b"\x93NUMPY" or len(raw) < 10:
        return None
    major = raw[6]
    if major == 1:
        header_len = int.from_bytes(raw[8:10], "little")
        start = 10
    else:
        header_len = int.from_bytes(raw[8:12], "little")
        start = 12
    header = raw[start:start + header_len]
    # Object arrays are stored as a pickle following the header.
    if b"'descr': '|O'" in header or b'"descr": "|O"' in header or b"|O" in header:
        return raw[start + header_len:]
    return None


def _scan_npy(p: Path, raw: bytes) -> ScanResult:
    payload = _npy_payload(raw)
    if payload is None:
        return ScanResult(path=str(p), format="npy (numeric, no pickle)")
    return ScanResult(path=str(p), format="npy (object array)",
                      streams=[analyze_stream(payload, p.name)])


def _scan_safetensors(p: Path, raw: bytes) -> ScanResult:
    """safetensors has no code-execution primitive; we only sanity-check it."""
    result = ScanResult(path=str(p), format="safetensors")
    if len(raw) < 8:
        result.error = "truncated safetensors header"
        return result
    header_len = int.from_bytes(raw[:8], "little")
    if header_len > SAFETENSORS_MAGIC_MAX_HEADER or header_len + 8 > len(raw):
        result.error = "implausible safetensors header length"
        return result
    try:
        json.loads(raw[8:8 + header_len])
    except Exception as exc:
        result.error = f"invalid safetensors header: {exc}"
    return result

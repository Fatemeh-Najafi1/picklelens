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

from .machine import Machine, Trace
from .rules import Severity, classify, downgrade, normalize
from .symbolic import Const, Global, Sym

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


def scan_file(path: str | Path) -> ScanResult:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        return ScanResult(path=str(p), format="unknown", error=str(exc))

    if p.suffix == ".safetensors":
        return _scan_safetensors(p, raw)
    if zipfile.is_zipfile(io.BytesIO(raw)):
        return _scan_zip(p, raw)
    if raw[:6] == b"\x93NUMPY":
        return _scan_npy(p, raw)
    if _looks_like_pickle(raw):
        return ScanResult(path=str(p), format="pickle",
                          streams=[analyze_stream(raw, p.name)])

    return ScanResult(path=str(p), format="unrecognized",
                      error="not a pickle, ZIP model archive, or safetensors file")


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
    except zipfile.BadZipFile as exc:
        result.error = f"corrupt archive: {exc}"

    if not result.streams and not result.error:
        result.format = "zip-archive (no pickle members)"
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

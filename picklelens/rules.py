"""Sink catalog, module-alias normalisation, and severity assignment.

Two ideas carry most of the detection value here:

1. **Alias normalisation.** `os.system` is really `nt.system` on Windows and
   `posix.system` on Linux, and `builtins` is `__builtin__` on Python 2. A
   catalog that lists only the friendly name misses payloads that name the
   implementation module - which is a one-line change for an attacker.

2. **Reachability.** A dangerous name that is merely *referenced* is not the
   same as one the program *calls*. We grade those differently instead of
   raising an identical alarm for both.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


# Modules that are the same thing under different names. Normalising these
# collapses a whole family of trivial blocklist bypasses.
MODULE_ALIASES = {
    "nt": "os",
    "posix": "os",
    "__builtin__": "builtins",
    "_socket": "socket",
    "_pickle": "pickle",
    "cPickle": "pickle",
    "_functools": "functools",
    "_operator": "operator",
    "_thread": "threading",
    "thread": "threading",
    "_subprocess": "subprocess",
    "_posixsubprocess": "subprocess",
    "_io": "io",
    "os.path": "posixpath",
}


def normalize(qualname: str) -> str:
    """Map a qualified name onto its canonical module."""
    module, _, name = qualname.partition(".")
    canonical = MODULE_ALIASES.get(module, module)
    return f"{canonical}.{name}" if name else canonical


@dataclass(frozen=True)
class Sink:
    """A callable whose invocation inside a pickle is meaningful."""

    pattern: str          # canonical qualname, or "module.*" for a whole module
    category: str
    severity: Severity
    note: str

    def matches(self, qualname: str) -> bool:
        target = normalize(qualname)
        if self.pattern.endswith(".*"):
            prefix = self.pattern[:-2]
            return target == prefix or target.startswith(prefix + ".")
        return target == self.pattern


# Ordered most-specific-first; the first match wins.
SINKS: tuple[Sink, ...] = (
    # -- direct code execution ------------------------------------------
    Sink("builtins.exec", "code_execution", Severity.CRITICAL,
         "executes arbitrary Python source at load time"),
    Sink("builtins.eval", "code_execution", Severity.CRITICAL,
         "evaluates an arbitrary Python expression at load time"),
    Sink("builtins.compile", "code_execution", Severity.HIGH,
         "compiles source into a code object"),
    Sink("types.FunctionType", "code_execution", Severity.CRITICAL,
         "materialises a callable from a raw code object"),
    Sink("types.CodeType", "code_execution", Severity.CRITICAL,
         "constructs a raw code object"),

    # -- process execution ------------------------------------------------
    Sink("os.system", "process_execution", Severity.CRITICAL,
         "runs a shell command"),
    Sink("os.popen", "process_execution", Severity.CRITICAL,
         "runs a shell command and captures its output"),
    Sink("subprocess.*", "process_execution", Severity.CRITICAL,
         "spawns an external process"),
    Sink("pty.spawn", "process_execution", Severity.CRITICAL,
         "spawns a process attached to a pseudo-terminal"),
    Sink("platform.popen", "process_execution", Severity.CRITICAL,
         "runs a shell command"),

    # -- interpreter / memory internals -----------------------------------
    Sink("ctypes.*", "interpreter_abuse", Severity.CRITICAL,
         "calls into native code or manipulates process memory"),
    Sink("cffi.*", "interpreter_abuse", Severity.CRITICAL,
         "calls into native code"),
    Sink("gc.get_referrers", "interpreter_abuse", Severity.HIGH,
         "walks live objects to reach otherwise unreachable state"),

    # -- nested deserialisation -------------------------------------------
    Sink("pickle.loads", "nested_deserialization", Severity.CRITICAL,
         "unpickles a further payload, hiding it from single-pass scanners"),
    Sink("pickle.load", "nested_deserialization", Severity.CRITICAL,
         "unpickles a further payload from a file"),
    Sink("marshal.loads", "nested_deserialization", Severity.CRITICAL,
         "loads a raw code object"),
    Sink("dill.*", "nested_deserialization", Severity.HIGH,
         "deserialises with a pickle superset"),
    Sink("shelve.open", "nested_deserialization", Severity.HIGH,
         "opens a pickle-backed store"),
    Sink("joblib.load", "nested_deserialization", Severity.HIGH,
         "loads a pickle-backed artifact"),
    Sink("numpy.load", "nested_deserialization", Severity.MEDIUM,
         "may unpickle when allow_pickle is set"),

    # -- reflection, the usual route around a blocklist --------------------
    Sink("builtins.getattr", "reflection", Severity.MEDIUM,
         "resolves an attribute by name, often to reach a hidden target"),
    Sink("builtins.__import__", "reflection", Severity.HIGH,
         "imports a module chosen at load time"),
    Sink("importlib.import_module", "reflection", Severity.HIGH,
         "imports a module chosen at load time"),
    Sink("operator.attrgetter", "reflection", Severity.MEDIUM,
         "resolves an attribute by name"),
    Sink("operator.methodcaller", "reflection", Severity.HIGH,
         "invokes a method chosen by name"),
    Sink("functools.partial", "reflection", Severity.MEDIUM,
         "defers a call, commonly used to smuggle the real target"),
    Sink("builtins.globals", "reflection", Severity.MEDIUM,
         "reaches the global namespace"),
    Sink("builtins.vars", "reflection", Severity.MEDIUM,
         "reaches an object namespace"),
    Sink("builtins.setattr", "reflection", Severity.MEDIUM,
         "mutates an attribute at load time"),

    # -- network ----------------------------------------------------------
    Sink("socket.*", "network", Severity.HIGH,
         "opens a network connection"),
    Sink("urllib.request.urlopen", "network", Severity.HIGH,
         "fetches a remote resource"),
    Sink("urllib.request.urlretrieve", "network", Severity.HIGH,
         "downloads a remote resource to disk"),
    Sink("requests.*", "network", Severity.HIGH,
         "performs an HTTP request"),
    Sink("http.client.*", "network", Severity.HIGH,
         "performs an HTTP request"),
    Sink("ftplib.*", "network", Severity.HIGH, "opens an FTP connection"),
    Sink("smtplib.*", "network", Severity.HIGH, "opens an SMTP connection"),
    Sink("telnetlib.*", "network", Severity.HIGH, "opens a telnet connection"),

    # -- filesystem and environment ---------------------------------------
    Sink("builtins.open", "filesystem", Severity.MEDIUM,
         "opens a file at load time"),
    Sink("io.open", "filesystem", Severity.MEDIUM, "opens a file at load time"),
    Sink("os.remove", "filesystem", Severity.HIGH, "deletes a file"),
    Sink("os.unlink", "filesystem", Severity.HIGH, "deletes a file"),
    Sink("os.rmdir", "filesystem", Severity.HIGH, "removes a directory"),
    Sink("shutil.rmtree", "filesystem", Severity.HIGH,
         "recursively deletes a directory"),
    Sink("shutil.move", "filesystem", Severity.MEDIUM, "moves a file"),
    Sink("shutil.copy", "filesystem", Severity.MEDIUM, "copies a file"),
    Sink("os.chmod", "filesystem", Severity.HIGH, "changes file permissions"),
    Sink("pathlib.Path", "filesystem", Severity.LOW,
         "constructs a filesystem path"),
    Sink("os.putenv", "environment", Severity.MEDIUM,
         "mutates the process environment"),
    Sink("os.environ", "environment", Severity.MEDIUM,
         "reads or mutates the process environment"),

    # -- encoding helpers, the usual payload wrapper -----------------------
    Sink("base64.*", "obfuscation", Severity.LOW,
         "decodes data, frequently wrapping a payload"),
    Sink("codecs.decode", "obfuscation", Severity.LOW,
         "decodes data, frequently wrapping a payload"),
    Sink("zlib.decompress", "obfuscation", Severity.LOW,
         "decompresses data, frequently wrapping a payload"),
    Sink("bz2.decompress", "obfuscation", Severity.LOW,
         "decompresses data, frequently wrapping a payload"),
    Sink("lzma.decompress", "obfuscation", Severity.LOW,
         "decompresses data, frequently wrapping a payload"),
)


def classify(qualname: str) -> Sink | None:
    """Return the first sink matching this callable, if any."""
    for sink in SINKS:
        if sink.matches(qualname):
            return sink
    return None


# A reference that is never called is real signal but weaker signal. Dropping
# an invoked finding by this many levels gives the referenced-only variant.
REFERENCE_ONLY_DOWNGRADE = 1


def downgrade(severity: Severity) -> Severity:
    return Severity(max(Severity.INFO, severity - REFERENCE_ONLY_DOWNGRADE))

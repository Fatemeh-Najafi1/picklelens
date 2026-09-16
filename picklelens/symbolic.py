"""Symbolic value model for the pickle stack machine.

Pickle is a stack language. Rather than executing it (which is the whole
danger), we interpret it over symbolic values so we can answer the only
question that matters: *what callables does this program actually invoke?*
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class Sym:
    """Base for every symbolic value on the machine stack."""

    def describe(self) -> str:  # pragma: no cover - overridden
        return "<value>"


@dataclass(frozen=True)
class Const(Sym):
    """A literal that appeared directly in the opcode stream."""

    value: Any

    def describe(self) -> str:
        return repr(self.value)


@dataclass(frozen=True)
class Global(Sym):
    """A `module.name` reference pushed by GLOBAL or STACK_GLOBAL."""

    module: str
    name: str
    # True when the module/name came off the stack (STACK_GLOBAL) rather than
    # from literal opcode arguments. Blocklist scanners that only read literal
    # GLOBAL arguments are blind to this form.
    dynamic: bool = False

    @property
    def qualname(self) -> str:
        return f"{self.module}.{self.name}"

    def describe(self) -> str:
        # A bare module reference (name == "") is just the module.
        return self.qualname if self.name else self.module


@dataclass(frozen=True)
class Attr(Sym):
    """Result of an attribute lookup, e.g. getattr(os, 'system')."""

    obj: Sym
    name: str

    def describe(self) -> str:
        return f"{self.obj.describe()}.{self.name}"


@dataclass(frozen=True)
class Call(Sym):
    """The result of invoking `func` with `args`."""

    func: Sym
    args: tuple[Sym, ...] = ()
    # How the call was made: reduce / newobj / inst / obj / build.
    via: str = "reduce"

    def describe(self) -> str:
        inner = ", ".join(a.describe() for a in self.args)
        return f"{self.func.describe()}({inner})"


@dataclass(frozen=True)
class Seq(Sym):
    """A tuple/list/set built on the stack."""

    items: tuple[Sym, ...]
    kind: str = "tuple"

    def describe(self) -> str:
        return "(" + ", ".join(i.describe() for i in self.items) + ")"


@dataclass(frozen=True)
class Mapping(Sym):
    items: tuple[tuple[Sym, Sym], ...] = ()

    def describe(self) -> str:
        return "{...}"


@dataclass(frozen=True)
class PersistentRef(Sym):
    """PERSID/BINPERSID - resolved by the unpickler's persistent_load hook."""

    ident: Sym

    def describe(self) -> str:
        return f"persistent_id({self.ident.describe()})"


@dataclass(frozen=True)
class Namespace(Sym):
    """The attribute namespace of a module/object, e.g. vars(os) or os.__dict__.

    Indexing it by a literal name is equivalent to attribute access, which is
    how a payload turns a module reference into a specific callable without
    ever naming that callable in a global.
    """

    obj: Sym

    def describe(self) -> str:
        return f"vars({self.obj.describe()})"


@dataclass(frozen=True)
class Extension(Sym):
    """EXT1/EXT2/EXT4 - resolved through copyreg's extension registry."""

    code: int

    def describe(self) -> str:
        return f"<extension {self.code}>"


@dataclass(frozen=True)
class Unknown(Sym):
    """A value we could not track precisely."""

    reason: str = ""

    def describe(self) -> str:
        return "<unknown>"


class Mark(Sym):
    """The MARK sentinel. Identity-compared, never a real value."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def describe(self) -> str:
        return "<mark>"


MARK = Mark()


def resolve(sym: Sym) -> Sym:
    """Collapse an Attr chain onto a concrete Global where possible.

    This is the core of catching aliased sinks. `getattr(os, "system")`
    arrives as Attr(Global("os", "path"?)...); if the base resolves to a
    module reference we can name the real target `os.system`. We also see
    through `getattr(__import__("os"), "system")`, where the base is a *call*
    to a dynamic importer that yields a bare module - the standard reflection
    route around a name blocklist.
    """
    if isinstance(sym, Attr):
        base = resolve(sym.obj)
        # Base is a call whose result is a bare module, e.g. __import__("os").
        if isinstance(base, Call):
            callee = resolve(base.func)
            if isinstance(callee, Global) and callee.name == "":
                return Global(callee.module, sym.name, dynamic=True)
        if isinstance(base, Global):
            # A bare module reference is modelled as Global(module, "") by the
            # import helpers; attribute access on it names a real target.
            if base.name == "":
                return Global(base.module, sym.name, dynamic=True)
            return Global(base.module, f"{base.name}.{sym.name}", dynamic=True)
    return sym

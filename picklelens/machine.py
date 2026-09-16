"""A non-executing interpreter for the pickle stack machine.

`pickletools.genops` decodes the opcode stream without running it. We replay
that stream over symbolic values, maintaining the same stack and memo the real
unpickler would, and record every invocation the program performs.

The output is a call graph, not a list of strings that appeared in the file.
That distinction is the whole point: a blocklist scanner asks "is the text
'os.system' in here?", we ask "does this program call os.system?".
"""
from __future__ import annotations

import pickletools
from dataclasses import dataclass, field

from .symbolic import (
    MARK,
    Attr,
    Call,
    Const,
    Extension,
    Global,
    Mapping,
    Mark,
    Namespace,
    PersistentRef,
    Seq,
    Sym,
    Unknown,
    resolve,
)

# Callables that perform attribute access, and therefore let an attacker reach
# a dangerous target without ever naming it in a GLOBAL opcode.
ATTRIBUTE_GETTERS = {
    "builtins.getattr",
    "__builtin__.getattr",
}

# Callables that import a module by name computed at load time.
DYNAMIC_IMPORTERS = {
    "importlib.import_module",
    "builtins.__import__",
    "__builtin__.__import__",
    "importlib._bootstrap._find_and_load",
}

# Callables that expose an object's attribute namespace as an indexable mapping.
NAMESPACE_GETTERS = {
    "builtins.vars",
    "__builtin__.vars",
    "builtins.globals",
}

# Callables that index a mapping/sequence by key.
ITEM_GETTERS = {
    "operator.getitem",
    "_operator.getitem",
}


@dataclass
class Invocation:
    """A single call the pickle program performs."""

    target: Sym           # resolved callee
    args: tuple[Sym, ...]
    via: str              # reduce | newobj | newobj_ex | inst | obj | build
    position: int         # byte offset in the pickle stream

    @property
    def qualname(self) -> str:
        t = resolve(self.target)
        if isinstance(t, Global):
            return t.qualname
        return t.describe()


@dataclass
class Trace:
    """Everything the machine learned from one pickle stream."""

    invocations: list[Invocation] = field(default_factory=list)
    globals_referenced: list[tuple[Global, int]] = field(default_factory=list)
    protocol: int = 0
    opcode_count: int = 0
    truncated: bool = False
    error: str | None = None
    # Opcodes that imply a resolution step we cannot follow statically.
    opaque: list[tuple[str, int]] = field(default_factory=list)

    @property
    def invoked_qualnames(self) -> set[str]:
        return {i.qualname for i in self.invocations}


class StackUnderflow(Exception):
    pass


class Machine:
    """Symbolic executor. Never imports, never calls, never deserializes."""

    def __init__(self, max_opcodes: int = 500_000) -> None:
        self.max_opcodes = max_opcodes

    def run(self, data: bytes) -> Trace:
        trace = Trace()
        stack: list[Sym] = []
        memo: dict[object, Sym] = {}

        def pop() -> Sym:
            if not stack:
                raise StackUnderflow("pop from empty stack")
            return stack.pop()

        def pop_mark() -> list[Sym]:
            items: list[Sym] = []
            while stack:
                v = stack.pop()
                if isinstance(v, Mark):
                    items.reverse()
                    return items
                items.append(v)
            raise StackUnderflow("no MARK on stack")

        def record(target: Sym, args: tuple[Sym, ...], via: str, pos: int) -> Sym:
            """Apply a call symbolically: log what is *invoked*, return the
            *value* it produces. These differ for reflection plumbing - calling
            vars(os) invokes `vars` but yields a namespace, and the produced
            value is what a later getitem needs to see to resolve os.system."""
            resolved = self._resolve_callee(target, args)

            # Plumbing that yields a module reference (dynamic import) or an
            # attribute namespace (vars/globals): record the helper itself at
            # its configured severity, but push the produced value so the chain
            # keeps resolving downstream.
            if isinstance(resolved, (Namespace,)) or (
                isinstance(resolved, Global) and resolved.name == ""
                and resolve(target) is not resolved
            ):
                helper = resolve(target)
                trace.invocations.append(Invocation(helper, args, via, pos))
                return resolved

            trace.invocations.append(Invocation(resolved, args, via, pos))
            return Call(resolved, args, via)

        try:
            for op, arg, pos in pickletools.genops(data):
                trace.opcode_count += 1
                if trace.opcode_count > self.max_opcodes:
                    trace.truncated = True
                    break
                name = op.name

                # --- frame / protocol bookkeeping -------------------------
                if name == "PROTO":
                    trace.protocol = int(arg or 0)
                elif name == "STOP":
                    break
                elif name == "FRAME":
                    pass

                # --- literals ---------------------------------------------
                elif name in (
                    "INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1",
                    "LONG4", "FLOAT", "BINFLOAT", "STRING", "BINSTRING",
                    "SHORT_BINSTRING", "UNICODE", "BINUNICODE",
                    "SHORT_BINUNICODE", "BINUNICODE8", "BINBYTES",
                    "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8",
                ):
                    stack.append(Const(arg))
                elif name == "NONE":
                    stack.append(Const(None))
                elif name == "NEWTRUE":
                    stack.append(Const(True))
                elif name == "NEWFALSE":
                    stack.append(Const(False))

                # --- stack shuffling --------------------------------------
                elif name == "MARK":
                    stack.append(MARK)
                elif name == "POP":
                    if stack:
                        stack.pop()
                elif name == "POP_MARK":
                    pop_mark()
                elif name == "DUP":
                    if stack:
                        stack.append(stack[-1])

                # --- memo -------------------------------------------------
                elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                    if stack:
                        memo[arg] = stack[-1]
                elif name == "MEMOIZE":
                    if stack:
                        memo[len(memo)] = stack[-1]
                elif name in ("GET", "BINGET", "LONG_BINGET"):
                    stack.append(memo.get(arg, Unknown("memo miss")))

                # --- containers -------------------------------------------
                elif name == "EMPTY_TUPLE":
                    stack.append(Seq((), "tuple"))
                elif name == "TUPLE":
                    stack.append(Seq(tuple(pop_mark()), "tuple"))
                elif name in ("TUPLE1", "TUPLE2", "TUPLE3"):
                    n = int(name[-1])
                    items = [pop() for _ in range(n)][::-1]
                    stack.append(Seq(tuple(items), "tuple"))
                elif name in ("EMPTY_LIST", "EMPTY_SET"):
                    stack.append(Seq((), "list" if "LIST" in name else "set"))
                elif name == "LIST":
                    stack.append(Seq(tuple(pop_mark()), "list"))
                elif name == "FROZENSET":
                    stack.append(Seq(tuple(pop_mark()), "frozenset"))
                elif name == "EMPTY_DICT":
                    stack.append(Mapping())
                elif name == "DICT":
                    items = pop_mark()
                    pairs = tuple(
                        (items[i], items[i + 1]) for i in range(0, len(items) - 1, 2)
                    )
                    stack.append(Mapping(pairs))
                elif name in ("APPEND", "ADDITEMS", "APPENDS", "SETITEM", "SETITEMS"):
                    # These mutate a container already on the stack. We drop the
                    # payload but keep the container, matching real semantics.
                    if name == "APPEND":
                        pop()
                    elif name == "SETITEM":
                        pop()
                        pop()
                    else:
                        pop_mark()

                # --- global resolution ------------------------------------
                elif name == "GLOBAL":
                    module, _, gname = str(arg).partition(" ")
                    g = Global(module, gname)
                    stack.append(g)
                    trace.globals_referenced.append((g, pos))
                elif name == "STACK_GLOBAL":
                    gname_sym = pop()
                    module_sym = pop()
                    g = self._stack_global(module_sym, gname_sym)
                    stack.append(g)
                    if isinstance(g, Global):
                        trace.globals_referenced.append((g, pos))

                # --- invocation -------------------------------------------
                elif name == "REDUCE":
                    args_sym = pop()
                    func = pop()
                    args = args_sym.items if isinstance(args_sym, Seq) else (args_sym,)
                    stack.append(record(func, tuple(args), "reduce", pos))
                elif name == "NEWOBJ":
                    args_sym = pop()
                    cls = pop()
                    args = args_sym.items if isinstance(args_sym, Seq) else (args_sym,)
                    stack.append(record(cls, tuple(args), "newobj", pos))
                elif name == "NEWOBJ_EX":
                    pop()  # kwargs
                    args_sym = pop()
                    cls = pop()
                    args = args_sym.items if isinstance(args_sym, Seq) else (args_sym,)
                    stack.append(record(cls, tuple(args), "newobj_ex", pos))
                elif name == "INST":
                    module, _, gname = str(arg).partition(" ")
                    args = tuple(pop_mark())
                    g = Global(module, gname)
                    trace.globals_referenced.append((g, pos))
                    stack.append(record(g, args, "inst", pos))
                elif name == "OBJ":
                    items = pop_mark()
                    if items:
                        cls, args = items[0], tuple(items[1:])
                        stack.append(record(cls, args, "obj", pos))
                    else:
                        stack.append(Unknown("empty OBJ"))
                elif name == "BUILD":
                    state = pop()
                    obj = pop()
                    # BUILD invokes __setstate__ on the object if it defines
                    # one - a real, frequently abused execution edge.
                    trace.invocations.append(
                        Invocation(Attr(obj, "__setstate__"), (state,), "build", pos)
                    )
                    stack.append(obj)

                # --- externally-resolved values ---------------------------
                elif name in ("PERSID", "BINPERSID"):
                    if name == "PERSID":
                        ident = Const(arg)
                    else:
                        ident = pop() if stack else Unknown()
                    stack.append(PersistentRef(ident))
                    trace.opaque.append((name, pos))
                elif name in ("EXT1", "EXT2", "EXT4"):
                    stack.append(Extension(int(arg or 0)))
                    trace.opaque.append((name, pos))
                elif name in ("NEXT_BUFFER", "READONLY_BUFFER"):
                    if name == "NEXT_BUFFER":
                        stack.append(Unknown("out-of-band buffer"))
                    trace.opaque.append((name, pos))
                else:
                    trace.opaque.append((name, pos))

        except StackUnderflow as exc:
            trace.error = f"malformed pickle: {exc}"
        except Exception as exc:  # pickletools raises on corrupt streams
            trace.error = f"{type(exc).__name__}: {exc}"

        return trace

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _stack_global(module_sym: Sym, name_sym: Sym) -> Sym:
        """STACK_GLOBAL takes module and name off the stack.

        Literal-argument scanners never see these strings as a global
        reference, so this opcode is a standard blocklist bypass.
        """
        module = module_sym.value if isinstance(module_sym, Const) else None
        gname = name_sym.value if isinstance(name_sym, Const) else None
        if isinstance(module, str) and isinstance(gname, str):
            return Global(module, gname, dynamic=True)
        return Unknown("STACK_GLOBAL with non-literal operands")

    @staticmethod
    def _resolve_callee(target: Sym, args: tuple[Sym, ...]) -> Sym:
        """Follow indirection so the recorded callee is the real target."""
        t = resolve(target)

        if isinstance(t, Global):
            qual = t.qualname
            # getattr(obj, "name") -> model the attribute, not the getattr.
            if qual in ATTRIBUTE_GETTERS and len(args) >= 2:
                attr = args[1]
                if isinstance(attr, Const) and isinstance(attr.value, str):
                    return resolve(Attr(args[0], attr.value))
            # import_module("os") -> a bare module reference we can name.
            if qual in DYNAMIC_IMPORTERS and args:
                mod = args[0]
                if isinstance(mod, Const) and isinstance(mod.value, str):
                    return Global(mod.value, "", dynamic=True)
            # vars(os) / globals() -> the indexable namespace of that object.
            if qual in NAMESPACE_GETTERS and args:
                return Namespace(resolve(args[0]))
            # operator.getitem(vars(os), "system") -> os.system. This is the
            # reflection route that names neither os nor system as a global.
            if qual in ITEM_GETTERS and len(args) >= 2:
                container, key = resolve(args[0]), args[1]
                if isinstance(container, Namespace) and isinstance(key, Const) \
                        and isinstance(key.value, str):
                    return resolve(Attr(container.obj, key.value))
        return t

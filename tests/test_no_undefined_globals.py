"""Every global a function references must actually exist.

Python resolves globals at call time, so a name that was never imported is not a
syntax error and not an import error -- it is a `NameError` on the first line of
the first run that happens to reach it. In a package where the expensive paths
are network-gated and the rare paths are the interesting ones (a recovered key,
a failing stratum), that can sit undetected for a long time.

This walks every function and method *defined* in the package, reads the
LOAD_GLOBAL instructions out of its bytecode, and requires each name to resolve
to a module global or a builtin. Cheap, offline, and exact for the bug class it
targets: it does not type-check anything, it only asserts the names exist.

Like `validate.gate_self_test`, it carries a negative self-test -- a checker that
cannot fail would quietly bless anything.
"""

import builtins
import dis
import importlib
import pkgutil
import types

import pytest

import qi_fingerprint


def _code_objects(code):
    """A function's own code plus every nested comprehension / closure body."""
    yield code
    for const in code.co_consts:
        if hasattr(const, "co_names"):
            yield from _code_objects(const)


def _codes_of(value):
    for holder in (value, getattr(value, "fget", None), getattr(value, "__func__", None)):
        code = getattr(holder, "__code__", None)
        if code is not None:
            yield code


def undefined_globals(module) -> list[tuple[str, str]]:
    """(qualified name, missing global) for everything defined in `module`."""
    known = set(vars(module)) | set(dir(builtins))
    filename = getattr(module, "__file__", None)
    missing: list[tuple[str, str]] = []

    def scan(label: str, code) -> None:
        # Only code written in this file: a dataclass-generated __repr__ or an
        # imported helper resolves against its own module's globals, not ours.
        if code.co_filename != filename:
            return
        for obj in _code_objects(code):
            for instr in dis.get_instructions(obj):
                if instr.opname == "LOAD_GLOBAL" and instr.argval not in known:
                    missing.append((label, instr.argval))

    for name, value in sorted(vars(module).items()):
        if getattr(value, "__module__", None) != module.__name__:
            continue  # imported, not defined here
        for code in _codes_of(value):
            scan(name, code)
        if isinstance(value, type):
            for attr, member in sorted(vars(value).items()):
                for code in _codes_of(member):
                    scan(f"{name}.{attr}", code)
    return missing


def _package_modules(package) -> list[str]:
    names = [package.__name__]
    for info in pkgutil.iter_modules(package.__path__):
        dotted = f"{package.__name__}.{info.name}"
        names.append(dotted)
        if info.ispkg:
            names.extend(_package_modules(importlib.import_module(dotted))[1:])
    return names


MODULES = _package_modules(qi_fingerprint)


def test_the_package_has_modules_to_check():
    """Guards against a discovery bug silently making this suite vacuous."""
    assert len(MODULES) > 10
    assert "qi_fingerprint.ingest.control" in MODULES


@pytest.mark.parametrize("dotted", MODULES)
def test_module_has_no_undefined_globals(dotted):
    module = importlib.import_module(dotted)
    problems = undefined_globals(module)
    assert not problems, "\n".join(
        f"{dotted}: {where} references undefined global `{name}`"
        for where, name in problems
    )


def test_checker_catches_a_missing_import():
    """The negative self-test: a checker that cannot fail proves nothing."""
    broken = types.ModuleType("broken")
    broken.__file__ = "<broken>"
    code = compile(
        "def uses_a_missing_name():\n"
        "    return sqrt_that_was_never_imported(4)\n",
        "<broken>",
        "exec",
    )
    exec(code, vars(broken))
    vars(broken)["uses_a_missing_name"].__module__ = "broken"

    assert undefined_globals(broken) == [
        ("uses_a_missing_name", "sqrt_that_was_never_imported")
    ]

"""Setup evidence for test fixtures, run with no network I/O: every call a test
module makes to a class or function it names is bound against that callable's
signature, so a fixture that passes a removed or misses a required argument is
found without a database or a server.

This is not a test of behaviour: nothing is called but ``inspect.signature``.
"""

from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path
from types import ModuleType


def forbid_sockets() -> None:
    """Refuse any socket use for the rest of the process, except reading the
    local host's name, which reaches no network."""

    def refuse(event: str, args: tuple) -> None:
        if event.startswith("socket.") and event != "socket.gethostname":
            raise RuntimeError("setup check attempted socket I/O: " + event)

    sys.addaudithook(refuse)


def bind_calls(module: ModuleType) -> int:
    """Bind every call in ``module``'s source to a class or function the module
    names, by its argument count and keyword names. Raises ``TypeError`` naming
    the first call that does not bind; returns how many calls were bound."""
    source = Path(module.__file__ or "").read_text()
    bound = 0
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        target = vars(module).get(node.func.id)
        if not (inspect.isclass(target) or inspect.isfunction(target)):
            continue
        if any(isinstance(arg, ast.Starred) for arg in node.args) or any(
            keyword.arg is None for keyword in node.keywords
        ):
            continue
        try:
            signature = inspect.signature(target)
        except (TypeError, ValueError):
            continue
        try:
            signature.bind(*node.args, **{kw.arg: None for kw in node.keywords if kw.arg})
        except TypeError as exc:
            raise TypeError(
                f"{Path(module.__file__ or '').name}:{node.lineno}: {node.func.id}(...) {exc}"
            ) from None
        bound += 1
    return bound

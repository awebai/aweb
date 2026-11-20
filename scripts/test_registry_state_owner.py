"""Only the serving-state owner and native lifecycle may read the registry slot."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


API_OWNERS = {
    "_shutdown_awid_registry_client",
    "_make_standalone_lifespan",
    "_make_library_lifespan",
}


def registry_slot_reads(source: str, path: str) -> list[int]:
    """Report loads regardless of the receiver variable's name."""
    if path == "aweb/application_state.py":
        return []
    reads = []

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.functions: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            self.functions.append(node.name)
            self.generic_visit(node)
            self.functions.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit(self, node: ast.AST) -> None:
            # These lifecycle functions define, replace and close the native slot.
            owns_slot = path == "aweb/api.py" and bool(API_OWNERS.intersection(self.functions))
            if not owns_slot and (
                isinstance(node, ast.Attribute)
                and isinstance(node.ctx, ast.Load)
                and node.attr == "awid_registry_client"
                or isinstance(node, ast.AugAssign)
                and isinstance(node.target, ast.Attribute)
                and node.target.attr == "awid_registry_client"
                or isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "awid_registry_client"
            ):
                reads.append(node.lineno)
            super().visit(node)

    Visitor().visit(ast.parse(source))
    return reads


class RegistryStateOwnerTests(unittest.TestCase):
    def test_server_consumers_use_application_registry_client(self) -> None:
        root = Path(__file__).resolve().parents[1] / "server" / "src"
        self.assertTrue(root.is_dir(), "Server source root is missing")
        violations = [
            f"{path.relative_to(root)}:{line}"
            for path in sorted(root.rglob("*.py"))
            for line in registry_slot_reads(path.read_text(), path.relative_to(root).as_posix())
        ]
        self.assertEqual(violations, [], "Registry consumers must use application_registry_client")

    def test_receiver_names_and_getattr_cannot_hide_a_read(self) -> None:
        self.assertEqual(
            registry_slot_reads(
                "x = renamed.awid_registry_client\ny = getattr(other, 'awid_registry_client', None)\nz.awid_registry_client += 1",
                "aweb/consumer.py",
            ),
            [1, 2, 3],
        )

    def test_slot_assignment_and_text_are_not_reads(self) -> None:
        self.assertEqual(
            registry_slot_reads(
                "state.awid_registry_client = value\nx = 'awid_registry_client'",
                "aweb/consumer.py",
            ),
            [],
        )

    def test_api_consumers_cannot_borrow_the_lifecycle_exception(self) -> None:
        self.assertEqual(
            registry_slot_reads(
                "def consumer(state):\n    return state.awid_registry_client", "aweb/api.py"
            ),
            [2],
        )
        self.assertEqual(
            registry_slot_reads(
                "def _make_library_lifespan(state):\n    return state.awid_registry_client",
                "aweb/api.py",
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()

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
    tree = ast.parse(source)
    strings: dict[str, set[str]] = {}
    resources: set[str] = set()

    def values(node: ast.AST) -> set[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value}
        return strings.get(node.id, set()) if isinstance(node, ast.Name) else set()

    def resource(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Name)
            and node.id in resources
            or isinstance(node, ast.Attribute)
            and node.attr == "native_resources"
            or isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and "native_resources" in values(node.args[1])
            or isinstance(node, ast.Subscript)
            and "native_resources" in values(node.slice)
            or isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("get", "__getitem__")
            and bool(node.args)
            and "native_resources" in values(node.args[0])
        )

    def mapping_receiver(node: ast.AST) -> ast.AST:
        if isinstance(node, ast.Attribute) and node.attr == "__dict__":
            return node.value
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "vars"
            and node.args
        ):
            return node.args[0]
        return node

    def registry_key(receiver: ast.AST, key: ast.AST) -> bool:
        names = values(key)
        return "awid_registry_client" in names or (
            "registry_client" in names and resource(mapping_receiver(receiver))
        )

    # Resolve simple name aliases without depending on their spelling or
    # statement order. Conservative unions also cover conditional assignment.
    assignments = [node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign))]
    changed = True
    while changed:
        changed = False
        for node in assignments:
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                if not isinstance(target, ast.Name):
                    continue
                before = len(strings.get(target.id, set())), target.id in resources
                strings.setdefault(target.id, set()).update(values(node.value))
                if resource(node.value):
                    resources.add(target.id)
                changed |= before != (len(strings[target.id]), target.id in resources)

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
            attribute = node.target if isinstance(node, ast.AugAssign) else node
            slot_read = (
                isinstance(attribute, ast.Attribute)
                and (isinstance(node, ast.AugAssign) or isinstance(attribute.ctx, ast.Load))
                and (
                    attribute.attr == "awid_registry_client"
                    or attribute.attr == "registry_client"
                    and resource(attribute.value)
                )
            )
            if isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "getattr"
                    and len(node.args) >= 2
                ):
                    slot_read |= registry_key(node.args[0], node.args[1])
                elif (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("get", "__getitem__")
                    and node.args
                ):
                    slot_read |= registry_key(node.func.value, node.args[0])
            if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
                slot_read |= registry_key(node.value, node.slice)
            if not owns_slot and slot_read:
                reads.append(node.lineno)
            super().visit(node)

    Visitor().visit(tree)
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

    def test_indirect_state_and_resource_reads_cannot_bypass_the_owner(self) -> None:
        for source, line in (
            ("key = 'awid_registry_client'\nx = getattr(state, key)", 2),
            ("key: str = 'awid_registry_client'\nx = getattr(state, key)", 2),
            ("ref = vars(state)['native_resources']\nx = ref.registry_client", 2),
            ("ref = state.__dict__.get('native_resources')\nx = ref.registry_client", 2),
            ("key = 'awid_registry_client'\nx = vars(state)[key]", 2),
            ("x = state.__dict__.get('awid_registry_client')", 1),
            ("x = state.__dict__['awid_registry_client']", 1),
            ("x = state.native_resources.registry_client", 1),
            ("ref = state.native_resources\nx = ref.registry_client", 2),
            (
                "ref = getattr(state, 'native_resources')\nother = ref\n"
                "key = 'registry_client'\nx = getattr(other, key)",
                4,
            ),
            ("ref = state.native_resources\nx = vars(ref).get('registry_client')", 2),
        ):
            with self.subTest(source=source):
                self.assertEqual(registry_slot_reads(source, "aweb/consumer.py"), [line])

    def test_explicit_runtime_registry_is_not_an_application_resource_read(self) -> None:
        self.assertEqual(
            registry_slot_reads("x = runtime.registry_client", "aweb/consumer.py"),
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

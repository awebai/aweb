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

    def scope_nodes(nodes):
        for node in nodes:
            yield node
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                yield from scope_nodes(ast.iter_child_nodes(node))

    def infer_aliases(nodes, parameters=()):
        nonlocal strings, resources
        local = list(scope_nodes(nodes))
        bound = {
            node.id
            for node in local
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        }
        bound.update(
            node.name
            for node in local
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        )
        bound.update(parameters)
        bound.difference_update(
            name
            for node in local
            if isinstance(node, (ast.Global, ast.Nonlocal))
            for name in node.names
        )
        strings = {
            name: set(names) for name, names in strings.items() if name not in bound
        }
        resources = resources - bound
        assignments = [
            node for node in local if isinstance(node, (ast.Assign, ast.AnnAssign))
        ]
        changed = True
        while changed:
            changed = False
            for node in assignments:
                for target in (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                ):
                    if not isinstance(target, ast.Name):
                        continue
                    before = len(strings.get(target.id, set())), target.id in resources
                    strings.setdefault(target.id, set()).update(values(node.value))
                    if resource(node.value):
                        resources.add(target.id)
                    changed |= before != (
                        len(strings[target.id]),
                        target.id in resources,
                    )

    infer_aliases(tree.body)

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.functions: list[str] = []
            self.class_parents = []

        def visit_FunctionDef(
            self, node: ast.FunctionDef | ast.AsyncFunctionDef
        ) -> None:
            nonlocal strings, resources
            previous = strings, resources
            for expression in (
                *node.decorator_list,
                *node.args.defaults,
                *node.args.kw_defaults,
            ):
                if expression is not None:
                    self.visit(expression)
            if node.returns is not None:
                self.visit(node.returns)
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
                node.args.vararg,
                node.args.kwarg,
            ):
                if argument is not None and argument.annotation is not None:
                    self.visit(argument.annotation)
            # Method bodies close over the enclosing function/module, not the class namespace.
            if self.class_parents and self.class_parents[-1] is not None:
                strings, resources = self.class_parents[-1]
            parameters = [
                arg.arg
                for arg in (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                )
            ]
            parameters.extend(
                arg.arg
                for arg in (node.args.vararg, node.args.kwarg)
                if arg is not None
            )
            infer_aliases(node.body, parameters)
            self.functions.append(node.name)
            self.class_parents.append(None)
            for statement in node.body:
                self.visit(statement)
            self.class_parents.pop()
            self.functions.pop()
            strings, resources = previous

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            nonlocal strings, resources
            previous = strings, resources
            for expression in (
                *node.decorator_list,
                *node.bases,
                *(keyword.value for keyword in node.keywords),
            ):
                self.visit(expression)
            infer_aliases(node.body)
            self.class_parents.append(previous)
            for statement in node.body:
                self.visit(statement)
            self.class_parents.pop()
            strings, resources = previous

        def visit(self, node: ast.AST) -> None:
            # These lifecycle functions define, replace and close the native slot.
            owns_slot = path == "aweb/api.py" and bool(
                API_OWNERS.intersection(self.functions)
            )
            attribute = node.target if isinstance(node, ast.AugAssign) else node
            slot_read = (
                isinstance(attribute, ast.Attribute)
                and (
                    isinstance(node, ast.AugAssign)
                    or isinstance(attribute.ctx, ast.Load)
                )
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
            for line in registry_slot_reads(
                path.read_text(), path.relative_to(root).as_posix()
            )
        ]
        self.assertEqual(
            violations, [], "Registry consumers must use application_registry_client"
        )

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
            (
                "ref = state.__dict__.get('native_resources')\nx = ref.registry_client",
                2,
            ),
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
                self.assertEqual(
                    registry_slot_reads(source, "aweb/consumer.py"), [line]
                )

    def test_aliases_respect_function_scope_and_shadowing(self) -> None:
        for source, expected in (
            (
                "def native_resources(state):\n    resources = state.native_resources\n"
                "    return application_registry_client(state)\n\n"
                "def default_mcp_factory(resources):\n    return resources.registry_client",
                [],
            ),
            (
                "def reader(state):\n    resources = state.native_resources\n"
                "    return resources.registry_client\n\n"
                "def explicit_factory(resources):\n    return resources.registry_client",
                [3],
            ),
            (
                "key = 'awid_registry_client'\ndef reader(state):\n    return getattr(state, key)",
                [3],
            ),
            (
                "key = 'awid_registry_client'\ndef reader(state):\n"
                "    key = 'other'\n    return getattr(state, key)",
                [],
            ),
            (
                "def outer(state):\n    ref = state.native_resources\n"
                "    def inner():\n        return ref.registry_client\n    return inner()",
                [4],
            ),
        ):
            with self.subTest(source=source):
                self.assertEqual(
                    registry_slot_reads(source, "aweb/consumer.py"), expected
                )

    def test_scope_headers_still_guard_evaluated_state_reads(self) -> None:
        for source, expected in (
            (
                "key = 'awid_registry_client'\ndef reader(client=getattr(state, key)):\n    pass",
                [2],
            ),
            ("@decorate(state.awid_registry_client)\ndef reader():\n    pass", [1]),
            ("class Reader(state.awid_registry_client):\n    pass", [1]),
        ):
            with self.subTest(source=source):
                self.assertEqual(
                    registry_slot_reads(source, "aweb/consumer.py"), expected
                )

    def test_explicit_runtime_registry_is_not_an_application_resource_read(
        self,
    ) -> None:
        self.assertEqual(
            registry_slot_reads("x = runtime.registry_client", "aweb/consumer.py"),
            [],
        )

    def test_api_consumers_cannot_borrow_the_lifecycle_exception(self) -> None:
        self.assertEqual(
            registry_slot_reads(
                "def consumer(state):\n    return state.awid_registry_client",
                "aweb/api.py",
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

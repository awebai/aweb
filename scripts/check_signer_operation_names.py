"""Keep signer operation names in the catalog, not generic production code."""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOMAINS = (
    Path("naapp-lib/src/aweb_naapp/runtime/protected_signer"),
    Path("server/src/aweb/protected_signing"),
)
CATALOG = Path("naapp-lib/src/aweb_naapp/runtime/protected_signer/catalog.py")
SELECTOR_FIELDS = frozenset({"operation", "variant", "family", "provider"})


def _selector(node):
    if isinstance(node, ast.Name):
        return node.id in SELECTOR_FIELDS
    if isinstance(node, ast.Attribute):
        return node.attr in SELECTOR_FIELDS
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get" and node.args and isinstance(node.args[0], ast.Constant)):
        return node.args[0].value in SELECTOR_FIELDS
    return (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant)
            and node.slice.value in SELECTOR_FIELDS)


def _literal(node):
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    return isinstance(node, (ast.Set, ast.List, ast.Tuple)) and any(_literal(item) for item in node.elts)


def selector_comparisons(source: str, suffix: str) -> list[int]:
    if suffix == ".py":
        found = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Compare):
                operands = [node.left, *node.comparators]
                if any(_selector(value) for value in operands) and any(_literal(value) for value in operands):
                    found.append(node.lineno)
            elif isinstance(node, ast.Match) and _selector(node.subject):
                if any(isinstance(part, ast.MatchValue) and _literal(part.value)
                       for case in node.cases for part in ast.walk(case.pattern)):
                    found.append(node.lineno)
        return sorted(set(found))
    if suffix not in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".html"}:
        return []
    fields = "|".join(sorted(SELECTOR_FIELDS))
    selector = rf"(?:[\w.$]+\.(?:{fields})|[\w.$]+\[[\"'](?:{fields})[\"']\]|\b(?:{fields}))"
    literal = r"[\"'][^\"'\n]*[\"']"
    equality = r"\s*(?:===?|!==?)\s*"
    pattern = re.compile(selector + equality + literal + "|" + literal + equality + selector)
    return [number for number, line in enumerate(source.splitlines(), 1) if pattern.search(line)]


def violations(root: Path = ROOT) -> list[str]:
    rows = json.loads((root / "docs/vectors/human-assurance-v1.json").read_text())["operations"]
    names = sorted({row["operation"] for row in rows}, key=lambda value: (-len(value), value))
    pattern = re.compile(r"(?<![\w.-])(?:" + "|".join(re.escape(name) for name in names) + r")(?![\w.-])")
    found = []
    for domain in DOMAINS:
        for path in sorted((root / domain).rglob("*")):
            relative = path.relative_to(root)
            if not path.is_file() or path.suffix == ".md" or "__pycache__" in path.parts :
                continue
            try:
                source = path.read_text()
            except UnicodeDecodeError:
                continue
            if relative == CATALOG:
                for node in ast.parse(source).body:
                    if (isinstance(node, (ast.Assign, ast.AnnAssign))
                        and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                        and pattern.search(node.value.value)):
                        found.append(f"{relative}:{node.lineno}: exported operation-name string")
                continue
            for number in selector_comparisons(source, path.suffix):
                found.append(f"{relative}:{number}: literal operation/variant/family/provider comparison")
            for number, line in enumerate(source.splitlines(), 1):
                for match in pattern.finditer(line):
                    found.append(f"{relative}:{number}: {match.group()}")
    return found


if __name__ == "__main__":
    errors = violations()
    if errors:
        print("Signer operation names outside catalog.py:\n" + "\n".join(errors))
        raise SystemExit(1)
    print("Signer operation name boundary passed (all contract rows, catalog.py only)")

"""Count product-table writes in Python test ASTs against reviewed file ceilings."""

from __future__ import annotations

import argparse
import ast
import hashlib
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tokenize
from typing import Iterator, Literal, NotRequired, TypedDict

CEILINGS = "tools/product-table-write-ceilings.json"
METHODS = frozenset(
    {
        "execute",
        "executemany",
        "execute_many",
        "fetch",
        "fetchrow",
        "fetchval",
        "fetchone",
        "fetchall",
        "fetch_one",
        "fetch_all",
        "fetch_value",
    }
)
# SQL tokenization happens only after the Python AST has selected a DB call.
# Comments and quoted values are single tokens, so their SQL-looking text is inert.
TOKEN = re.compile(
    r"--[^\n]*|/\*.*?\*/|'(?:''|[^'])*'|\$([A-Za-z_]\w*|)\$.*?\$\1\$|\{\{\s*tables\.[A-Za-z_]\w*\s*\}\}|\{dynamic\}|\"(?:\"\"|[^\"])*\"|[A-Za-z_]\w*|[^\s]",
    re.DOTALL,
)
IDENTIFIER = re.compile(r"[A-Za-z_]\w*\Z")
MARKER = "unreachable-state:"
NONLITERAL_MARKER = "nonliteral-call:"


class ScanError(Exception):
    """The scan or reviewed baseline cannot be established."""


@dataclass(frozen=True)
class Write:
    file: str
    line: int
    operation: str
    table: str
    candidate_namespaces: tuple[str, ...]
    reason: str | None


class Counts(TypedDict):
    marked: int
    unmarked: int


class TableCounts(Counts):
    candidate_namespaces: list[str]


class UnresolvedCall(TypedDict):
    file: str
    line: int
    method: str
    operation: NotRequired[str]
    reason: NotRequired[str]


@dataclass
class Report:
    source_sha: str
    scanned_files: int
    product_table_names: int
    unmarked: int
    marked: int
    by_file: dict[str, Counts]
    by_table: dict[str, TableCounts]
    writes: list[Write]
    excluded: list[dict[str, object]]
    unresolved_calls: list[UnresolvedCall]
    nonliteral_by_file: dict[str, int]
    marked_nonliteral_by_file: dict[str, int]
    markers_by_file: dict[str, int]
    schema_version: int = 1
    scope: str = "Python test/helper ASTs; execute/fetch literal SQL INSERT/UPDATE/DELETE statement sites"


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, timeout=30
    )
    if result.returncode:
        raise ScanError(
            f"cannot inspect synchronized main/source: {result.stderr.strip()}. Synchronize origin/main before running make check-product-table-writes; the checker never fetches."
        )
    return result.stdout


def test_file(path: Path) -> bool:
    return path.suffix == ".py" and (
        bool({"tests", "test", "testing", "e2e"}.intersection(path.parts))
        or path.parts[:2] == ("scripts", "test-egress")
        or path.name.startswith("test_")
        or path.name.endswith("_test.py")
        or path.stem in {"conftest", "testing"}
    )


def tokens(sql: str) -> list[str]:
    return [
        m.group() for m in TOKEN.finditer(sql) if not m.group().startswith(("--", "/*"))
    ]


def identifier(token: str) -> str | None:
    if token.startswith('"') and token.endswith('"'):
        return token[1:-1].replace('""', '"')
    if IDENTIFIER.fullmatch(token):
        return token.lower()
    if token == "{dynamic}":
        return token
    return None


def target(parts: list[str], start: int) -> tuple[str, str] | None:
    if start >= len(parts):
        return None
    word = parts[start]
    if word.startswith("{{"):
        name = word.split(".", 1)[1].rstrip("} ")
        return "{{tables}}." + name, name
    first = identifier(word)
    if first is None:
        return None
    if start + 2 < len(parts) and parts[start + 1] == ".":
        second = identifier(parts[start + 2])
        if second is not None:
            return first + "." + second, second
        return None
    return first, first


def statements(sql: str) -> Iterator[list[str]]:
    statement: list[str] = []
    for word in tokens(sql):
        if word == ";":
            if statement:
                yield statement
            statement = []
        else:
            statement.append(word)
    if statement:
        yield statement


def write_targets(sql: str) -> Iterator[tuple[str, str, str]]:
    for parts in statements(sql):
        op = parts[0].upper()
        start = 1
        if op == "INSERT" and len(parts) > 1 and parts[1].upper() == "INTO":
            start = 2
        elif op == "DELETE" and len(parts) > 1 and parts[1].upper() == "FROM":
            start = 2
        elif op != "UPDATE":
            continue
        if start < len(parts) and parts[start].upper() == "ONLY":
            start += 1
        found = target(parts, start)
        if found:
            yield op, *found


def inventory(root: Path, paths: list[Path]) -> dict[str, set[str]]:
    tables: dict[str, set[str]] = defaultdict(set)
    for path in paths:
        if (
            path.suffix != ".sql"
            or "src" not in path.parts
            or not any("migration" in p for p in path.parts)
        ):
            continue
        # Namespaces identify migration owners; pgdbm may mount them elsewhere.
        namespace = (
            "aweb"
            if path.parts[0] == "server"
            else "awid"
            if path.parts[0] == "awid"
            else path.parts[path.parts.index("src") + 1]
        )
        for parts in statements((root / path).read_text()):
            upper = [p.upper() for p in parts]
            if upper[:2] != ["CREATE", "TABLE"]:
                continue
            start = 5 if upper[2:5] == ["IF", "NOT", "EXISTS"] else 2
            found = target(parts, start)
            if found:
                qualified, name = found
                tables[name].add(
                    qualified.rsplit(".", 1)[0]
                    if "." in qualified and not qualified.startswith("{{")
                    else namespace
                )
    if not tables:
        raise ScanError(
            "no product migration tables found; restore the product migrations and rerun make check-product-table-writes"
        )
    return tables


def bindings(scope: ast.AST) -> dict[str, ast.expr | None]:
    result: dict[str, ast.expr | None] = {}

    def bind(name: str, value: ast.expr | None) -> None:
        result[name] = None if name in result else value

    def visit(node: ast.AST, *, dynamic: bool = False) -> None:
        if node is not scope and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            if not isinstance(node, ast.Lambda):
                bind(node.name, None)
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target_node in targets:
                if len(targets) == 1 and isinstance(target_node, ast.Name):
                    bind(target_node.id, None if dynamic else node.value)
                else:
                    visit(target_node, dynamic=True)
            if node.value is not None:
                visit(node.value, dynamic=dynamic)
            return
        # Any other store/delete (loop, +=, with, walrus, unpacking, comprehension)
        # shadows an outer literal. Do not mistake a stale SELECT for resolved SQL.
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bind(node.id, None)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bind(alias.asname or alias.name.split(".")[0], None)
        elif (
            isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar))
            and node.name is not None
        ):
            bind(node.name, None)
        elif isinstance(node, ast.MatchMapping) and node.rest is not None:
            bind(node.rest, None)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                bind(name, None)
        for child in ast.iter_child_nodes(node):
            visit(
                child,
                dynamic=dynamic or isinstance(node, (ast.For, ast.AsyncFor, ast.While)),
            )

    visit(scope)
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        parameters = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
        parameters.extend(
            arg for arg in (scope.args.vararg, scope.args.kwarg) if arg is not None
        )
        for argument in parameters:
            result[argument.arg] = None
    return result


def literal(
    node: ast.AST, names: dict[str, ast.expr | None], seen: frozenset[str] = frozenset()
) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id not in seen:
        value = names.get(node.id)
        return literal(value, names, seen | {node.id}) if value is not None else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = literal(node.left, names, seen), literal(node.right, names, seen)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.JoinedStr):
        return "".join(
            value.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
            else "{dynamic}"
            for value in node.values
        )
    return None


def scan_file(
    root: Path, path: Path, tables: dict[str, set[str]]
) -> tuple[list[Write], list[dict[str, object]], list[UnresolvedCall], int]:
    source = (root / path).read_text()
    tree = ast.parse(source, filename=path.as_posix())
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    lines = source.splitlines()
    comments: dict[int, str] = {}
    nonliteral_markers: dict[int, str] = {}
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type != tokenize.COMMENT:
            continue
        line, column = token.start
        comment = token.string[1:].strip()
        inline = bool(lines[line - 1][:column].strip())
        if not inline:
            comments[line] = comment
        if comment.startswith(NONLITERAL_MARKER):
            explanation = comment[len(NONLITERAL_MARKER) :].strip()
            if not explanation:
                raise ScanError(f"{path}:{line}: empty nonliteral-call marker")
            if not inline:
                raise ScanError(f"{path}:{line}: nonliteral-call marker must be inline")
            nonliteral_markers[line] = explanation
    scopes = {
        node: bindings(node)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef))
    }
    writes: list[Write] = []
    excluded: list[dict[str, object]] = []
    unresolved: list[UnresolvedCall] = []
    marked_statements: set[int] = set()
    marked_nonliteral_lines: set[int] = set()
    for call in ast.walk(tree):
        if (
            not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Attribute)
            or call.func.attr not in METHODS
        ):
            continue
        expression = (
            call.args[0]
            if call.args
            else next(
                (
                    k.value
                    for k in call.keywords
                    if k.arg in {"query", "sql", "statement"}
                ),
                None,
            )
        )
        if expression is None:
            continue
        node: ast.AST = call
        statement: ast.stmt | None = None
        scope_chain: list[ast.AST] = []
        function_header = False
        while node in parents:
            child, node = node, parents[node]
            if statement is None and isinstance(node, ast.stmt):
                statement = node
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope_chain.append(node)
                function_header |= child not in node.body
            elif isinstance(
                node,
                (
                    ast.Lambda,
                    ast.ClassDef,
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                    ast.GeneratorExp,
                ),
            ):
                scope_chain.append(node)
        # Only module and ordinary function bindings are modeled. Never borrow
        # an outer literal through a lambda/class/comprehension or closure.
        names: dict[str, ast.expr | None] = {}
        if not function_header:
            if not scope_chain:
                names = scopes[tree]
            elif isinstance(scope_chain[0], (ast.FunctionDef, ast.AsyncFunctionDef)):
                names = scopes[scope_chain[0]]
                if len(scope_chain) == 1:
                    names = scopes[tree] | names
        sql = literal(expression, names)
        if sql is None:
            row = UnresolvedCall(
                file=path.as_posix(), line=call.lineno, method=call.func.attr
            )
            if call.lineno in nonliteral_markers:
                if call.lineno in marked_nonliteral_lines:
                    raise ScanError(
                        f"{path}:{call.lineno}: a nonliteral-call marker must identify one unresolved call"
                    )
                marked_nonliteral_lines.add(call.lineno)
                row["reason"] = nonliteral_markers[call.lineno]
            unresolved.append(row)
            continue
        targets = list(write_targets(sql))
        if not targets:
            continue
        line = statement.lineno if statement is not None else call.lineno
        comment = comments.get(line - 1, "")
        reason = comment[len(MARKER) :].strip() if comment.startswith(MARKER) else None
        if reason == "":
            raise ScanError(
                f"{path}:{line - 1}: empty unreachable-state marker; name the specific historical/corrupt/interrupted state"
            )
        if reason is not None:
            if line in marked_statements:
                raise ScanError(
                    f"{path}:{line}: one marker covers multiple write calls; put each call and its specific marker on a separate statement"
                )
            if sum(name in tables for _, _, name in targets) > 1:
                raise ScanError(
                    f"{path}:{line}: one marker covers multiple product writes; use a separate marked call for each write"
                )
            marked_statements.add(line)
        for operation, qualified, name in targets:
            if name == "{dynamic}":
                unresolved.append(
                    {
                        "file": path.as_posix(),
                        "line": call.lineno,
                        "method": call.func.attr,
                        "operation": operation,
                    }
                )
                continue
            if name not in tables:
                excluded.append(
                    {
                        "file": path.as_posix(),
                        "line": call.lineno,
                        "operation": operation,
                        "table": qualified,
                    }
                )
                continue
            writes.append(
                Write(
                    path.as_posix(),
                    call.lineno,
                    operation,
                    qualified,
                    tuple(sorted(tables[name])),
                    reason,
                )
            )
    unused_markers = nonliteral_markers.keys() - marked_nonliteral_lines
    if unused_markers:
        raise ScanError(
            f"{path}:{min(unused_markers)}: a nonliteral-call marker must identify one unresolved call"
        )
    return (
        writes,
        excluded,
        unresolved,
        sum(c.startswith(MARKER) for c in comments.values()),
    )


def scan(root: Path) -> Report:
    paths = sorted(
        {
            Path(p)
            for p in git(
                root, "ls-files", "--cached", "--others", "--exclude-standard"
            ).splitlines()
            if (root / p).is_file()
        }
    )
    tables = inventory(root, paths)
    writes: list[Write] = []
    excluded: list[dict[str, object]] = []
    unresolved: list[UnresolvedCall] = []
    files = [path for path in paths if test_file(path)]
    markers_by_file: dict[str, int] = {}
    for path in files:
        found, other, dynamic, marker_count = scan_file(root, path, tables)
        if marker_count:
            markers_by_file[path.as_posix()] = marker_count
        writes.extend(found)
        excluded.extend(other)
        unresolved.extend(dynamic)
    by_file: dict[str, Counts] = {}
    by_table: dict[str, TableCounts] = {}
    for item in writes:
        key: Literal["marked", "unmarked"] = (
            "marked" if item.reason is not None else "unmarked"
        )
        by_file.setdefault(item.file, {"marked": 0, "unmarked": 0})[key] += 1
        row = by_table.setdefault(
            item.table,
            {
                "marked": 0,
                "unmarked": 0,
                "candidate_namespaces": list(item.candidate_namespaces),
            },
        )
        row[key] += 1
    return Report(
        source_sha=git(root, "rev-parse", "HEAD").strip(),
        scanned_files=len(files),
        product_table_names=len(tables),
        unmarked=sum(w.reason is None for w in writes),
        marked=sum(w.reason is not None for w in writes),
        by_file=dict(sorted(by_file.items())),
        by_table=dict(sorted(by_table.items())),
        writes=sorted(writes, key=lambda w: (w.file, w.line, w.table)),
        excluded=excluded,
        unresolved_calls=unresolved,
        nonliteral_by_file=dict(
            sorted(
                Counter(
                    row["file"] for row in unresolved if "reason" not in row
                ).items()
            )
        ),
        marked_nonliteral_by_file=dict(
            sorted(
                Counter(row["file"] for row in unresolved if "reason" in row).items()
            )
        ),
        markers_by_file=markers_by_file,
    )


class Budget(TypedDict):
    files: dict[str, int]
    marked_files: dict[str, int]
    nonliteral_files: dict[str, int]
    marked_nonliteral_files: dict[str, int]


def ceilings(raw: str) -> Budget:
    value = json.loads(raw)
    required = {"schema_version", "files", "nonliteral_files"}
    optional = {"marked_files", "marked_nonliteral_files"}
    if (
        not isinstance(value, dict)
        or not required <= value.keys() <= required | optional
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ScanError(
            "invalid product-write ceiling shape; restore the reviewed manifest"
        )
    # Existing manifests predate the marked budgets; absence grants zero.
    for group in (
        "files",
        "marked_files",
        "nonliteral_files",
        "marked_nonliteral_files",
    ):
        value.setdefault(group, {})
        if not isinstance(value[group], dict):
            raise ScanError(f"{group} ceilings must map files to positive counts")
        for file, count in value[group].items():
            if (
                not isinstance(file, str)
                or not test_file(Path(file))
                or Path(file).is_absolute()
                or ".." in Path(file).parts
                or type(count) is not int
                or count < 1
            ):
                raise ScanError(
                    "ceilings require relative test paths and positive integer counts; remove cleared entries"
                )
    return Budget(
        files=value["files"],
        marked_files=value["marked_files"],
        nonliteral_files=value["nonliteral_files"],
        marked_nonliteral_files=value["marked_nonliteral_files"],
    )


def reviewed_ceilings_text(root: Path) -> str | None:
    """Synchronized main's ceilings file, the only main content this check reads."""
    git(root, "rev-parse", "--verify", "refs/remotes/origin/main")
    exists = git(
        root, "ls-tree", "--name-only", "refs/remotes/origin/main", "--", CEILINGS
    ).strip()
    return git(root, "show", f"refs/remotes/origin/main:{CEILINGS}") if exists else None


def reviewed_identity(root: Path) -> str:
    text = reviewed_ceilings_text(root)
    if text is None:
        return "absent"
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def violations(root: Path, report: Report) -> list[str]:
    candidate = ceilings((root / CEILINGS).read_text())
    text = reviewed_ceilings_text(root)
    reviewed = ceilings(text) if text is not None else None
    errors: list[str] = []
    reviewed_marked = reviewed["marked_files"] if reviewed is not None else {}
    for file, count in sorted(candidate["marked_files"].items()):
        previous = reviewed_marked.get(file, 0)
        if count <= previous:
            continue
        if "migration" not in Path(file).name:
            errors.append(
                f"{file}: a marked writes ceiling increase above reviewed {previous} requires a filename containing 'migration'"
            )
        markers = report.markers_by_file.get(file, 0)
        if count != markers:
            errors.append(
                f"{file}: marked writes ceiling {count} must match {markers} unreachable-state markers for a raise above reviewed {previous}"
            )
    actual_writes = Counter(w.file for w in report.writes if w.reason is None)
    actual_marked = Counter(w.file for w in report.writes if w.reason is not None)
    groups: tuple[
        tuple[
            Literal[
                "files", "marked_files", "nonliteral_files", "marked_nonliteral_files"
            ],
            str,
            dict[str, int],
        ],
        ...,
    ] = (
        ("files", "unmarked writes", dict(actual_writes)),
        ("marked_files", "marked writes", dict(actual_marked)),
        ("nonliteral_files", "nonliteral calls", report.nonliteral_by_file),
        (
            "marked_nonliteral_files",
            "marked nonliteral calls",
            report.marked_nonliteral_by_file,
        ),
    )
    for key, label, actual in groups:
        limits = candidate[key]
        if reviewed is not None and key in ("files", "nonliteral_files"):
            reviewed_limits = reviewed[key]
            errors.extend(
                f"{file}: {label} ceiling {count} > reviewed {reviewed_limits.get(file, 0)}"
                for file, count in limits.items()
                if count > reviewed_limits.get(file, 0)
            )
        errors.extend(
            f"{file}: {label} {count} > {limits.get(file, 0)}"
            for file, count in sorted(actual.items())
            if count > limits.get(file, 0)
        )
        errors.extend(
            f"{label}: lower {file} to {actual.get(file, 0)} in {CEILINGS} ({key}); remove the entry at zero"
            for file, count in sorted(limits.items())
            if count > actual.get(file, 0)
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the full per-file/per-table and site report",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="inventory without ceiling comparison (not a gate check)",
    )
    parser.add_argument(
        "--reviewed-identity",
        action="store_true",
        help="print the identity of synchronized main's ceilings, the check's only main input",
    )
    args = parser.parse_args()
    try:
        if args.reviewed_identity:
            print(reviewed_identity(args.root))
            return 0
        report = scan(args.root)
        errors = [] if args.report_only else violations(args.root, report)
        if args.json:
            print(
                json.dumps(
                    asdict(report) | {"violations": errors}, indent=2, sort_keys=True
                )
            )
        else:
            print(
                f"Product-table writes: {report.unmarked} unmarked, {report.marked} marked in {len(report.by_file)} files; {len(report.excluded)} non-product targets; {len(report.unresolved_calls)} nonliteral calls"
            )
            for file, counts in report.by_file.items():
                print(
                    f"{file}: {counts['unmarked']} unmarked, {counts['marked']} marked"
                )
            for table, counts in report.by_table.items():
                print(f"table {table}: {counts}")
            for write in report.writes:
                if write.reason is not None:
                    print(
                        f"marked {write.file}:{write.line} {write.table}: {write.reason}"
                    )
            for excluded in report.excluded:
                print(
                    f"non-product target {excluded['file']}:{excluded['line']}: {excluded['table']}"
                )
            for unresolved in report.unresolved_calls:
                reason = unresolved.get("reason")
                label = "marked nonliteral call" if reason else "nonliteral call"
                detail = f": {reason}" if reason else ""
                print(
                    f"{label} {unresolved['file']}:{unresolved['line']}: {unresolved['method']}{detail}"
                )
            for error in errors:
                print(error)
            if errors:
                print(
                    "Build test state through the product/shared builders. For unreachable states, declare the exact marked count and put one specific marker above each write. Lower cleared ceilings."
                )
        return int(bool(errors))
    except (
        ScanError,
        OSError,
        SyntaxError,
        tokenize.TokenError,
        UnicodeError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"Product-table write setup failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

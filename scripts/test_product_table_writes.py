"""CLI controls for the product-table write ceiling, with real Git and Python AST."""

from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

CHECKER = Path(__file__).with_name("product_table_writes.py")


class ProductTableWrites(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.git("init", "-q")
        self.write(
            "server/src/aweb/migrations/001.sql",
            "CREATE TABLE {{tables.agents}} (id int); CREATE TABLE public.teams(id int);",
        )
        self.write(
            "awid/src/awid_service/migrations/001.sql",
            "CREATE TABLE {{tables.teams}}(id int);",
        )
        self.write(
            "tools/product-table-write-ceilings.json",
            '{"schema_version":1,"nonliteral_files":{},"files":{}}\n',
        )
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "reviewed base",
        )
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.root, check=True, capture_output=True, text=True
        ).stdout.strip()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def run_check(self, *args):
        return subprocess.run(
            [sys.executable, str(CHECKER), "--root", str(self.root), *args],
            capture_output=True,
            text=True,
            env=dict(os.environ, UV_OFFLINE="1"),
        )

    def report(self, source):
        self.write("server/tests/test_world.py", source)
        result = self.run_check("--report-only", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_ast_calls_count_writes_not_assertions_comments_or_reads(self):
        report = self.report("""
# INSERT INTO agents is not a call.
assert "DELETE FROM agents" == expected
async def scenario(db):
    await db.execute("-- comment\\n INSERT INTO {{tables.agents}} (id) VALUES ($1)", 1)
    await db.fetch_one('UPDATE "public"."teams" SET id=1 RETURNING id')
    await db.fetch_all("SELECT 'INSERT INTO agents'")
    await db.execute("INSERT INTO test_scratch VALUES (1)")
    await db.execute("DELETE FROM agents; UPDATE teams SET id=2")
""")
        self.assertEqual(report["unmarked"], 4)
        self.assertEqual(report["excluded"][0]["table"], "test_scratch")
        self.assertEqual(report["by_table"]["{{tables}}.agents"]["unmarked"], 1)
        self.assertEqual(report["by_table"]["public.teams"]["unmarked"], 1)
        self.assertEqual(
            report["by_table"]["teams"]["candidate_namespaces"], ["awid", "public"]
        )

    def test_marker_is_statement_local_and_does_not_increase_allowance(self):
        report = self.report("""
async def scenario(db):
    # unreachable-state: pre-migration missing membership, no longer creatable
    row = await db.fetch_one("INSERT INTO agents VALUES (1) RETURNING id")
    await db.execute("DELETE FROM agents")
""")
        self.assertEqual((report["marked"], report["unmarked"]), (1, 1))
        self.assertIn("pre-migration", report["writes"][0]["reason"])
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("1 > 0", result.stdout)
        self.write(
            "server/tests/test_world.py",
            'async def f(db):\n    # unreachable-state: corrupt orphan left by interrupted migration\n    await db.execute("DELETE FROM agents")\n',
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("marked writes 1 > 0", result.stdout)

    def test_literals_aliases_fstrings_and_keyword_queries(self):
        report = self.report("""
SQL = "INSERT INTO " + "agents VALUES (1)"
async def f(db, schema):
    await db.execute(SQL)
    await db.execute(query=f"DELETE FROM {schema}.teams WHERE id=1")
    await db.fetchrow("UPDATE teams SET id=1")
    await db.executemany("INSERT INTO agents VALUES ($1)", [(1,), (2,)])
""")
        self.assertEqual(report["unmarked"], 4)
        self.assertEqual(report["by_table"]["{dynamic}.teams"]["unmarked"], 1)

    def test_gate_shaped_ref_and_inflation_controls(self):
        self.git("checkout", "--detach", "-q")
        self.write(
            "server/tests/test_world.py",
            'async def f(db):\n    await db.execute("INSERT INTO agents VALUES (1)")\n',
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.write(
            "tools/product-table-write-ceilings.json",
            '{"schema_version":1,"nonliteral_files":{},"files":{"server/tests/test_world.py":1}}',
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("reviewed", result.stdout)
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        result = self.run_check()
        self.assertEqual(result.returncode, 2)
        self.assertIn("synchronized main", result.stderr)
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.write(
            "server/tests/test_world.py",
            'async def f(product):\n    await product.register_actor("neighbor")\n',
        )
        self.write(
            "tools/product-table-write-ceilings.json",
            '{"schema_version":1,"nonliteral_files":{},"files":{}}',
        )
        self.assertEqual(self.run_check().returncode, 0)

    def test_existing_allowance_can_only_decrease_new_files_get_zero(self):
        self.write(
            "tools/product-table-write-ceilings.json",
            '{"schema_version":1,"nonliteral_files":{},"files":{"server/tests/test_world.py":2}}',
        )
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "existing debt",
        )
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.write(
            "server/tests/test_world.py",
            'async def f(db):\n    await db.execute("DELETE FROM agents")\n',
        )
        self.write(
            "tools/product-table-write-ceilings.json",
            '{"schema_version":1,"nonliteral_files":{},"files":{"server/tests/test_world.py":1}}',
        )
        self.assertEqual(self.run_check().returncode, 0)
        self.write(
            "server/tests/test_new.py",
            'async def f(db):\n    await db.execute("DELETE FROM agents")\n',
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("test_new.py", result.stdout)

    def test_real_stage_records_violation_alongside_later_targets(self):
        log = self.root / "logs"
        log.mkdir()
        (log / "host-published-port.log").write_text("fixture host preflight\n")
        self.write(
            "Makefile",
            f"check-product-table-writes:\n\t@{sys.executable} {CHECKER} --root {self.root}\n.DEFAULT:\n\t@echo $@ >> calls\n",
        )
        source = CHECKER.with_name("candidate-suite.sh")
        for body, expected in (
            ("await db.execute('INSERT INTO agents VALUES (1)')", 2),
            ("await product.register_actor()", 0),
        ):
            with self.subTest(body=body):
                self.write(
                    "server/tests/test_world.py",
                    "async def f(db, product):\n    " + body + "\n",
                )
                self.write("calls", "")
                result = subprocess.run(
                    ["bash", str(source), "checks"],
                    cwd=self.root,
                    env=dict(os.environ, CANDIDATE_LOG_DIR=str(log)),
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    result.returncode, expected, result.stdout + result.stderr
                )
                calls = (self.root / "calls").read_text().splitlines()
                self.assertEqual(calls[0], "check-python-static")
                self.assertIn("test-shipping", calls)
                self.assertIn(
                    "checks/check-product-table-writes\t"
                    + ("PASSED" if expected == 0 else "FAILED"),
                    (log / "summary.tsv").read_text(),
                )

    def test_matching_name_in_any_schema_counts_and_unknown_target_is_listed(self):
        report = self.report(
            'async def f(db):\n    await db.execute("INSERT INTO temporary.agents VALUES (1)")\n    await db.execute("DELETE FROM unrelated_scratch")\n'
        )
        self.assertEqual(report["unmarked"], 1)
        self.assertEqual(report["writes"][0]["table"], "temporary.agents")
        self.assertEqual(report["excluded"][0]["table"], "unrelated_scratch")

    def test_one_marker_cannot_cover_two_calls_and_shadowed_literals_are_unresolved(
        self,
    ):
        self.write(
            "server/tests/test_world.py",
            "async def f(db):\n    # unreachable-state: interrupted migration\n    await gather(db.execute('DELETE FROM agents'), db.execute('DELETE FROM teams'))\n",
        )
        refused = self.run_check()
        self.assertEqual(refused.returncode, 2)
        self.assertIn("multiple write calls", refused.stderr)
        report = self.report(
            "SQL = 'DELETE FROM agents'\nasync def f(db, SQL):\n    await db.execute(SQL)\n"
        )
        self.assertEqual(report["unmarked"], 0)
        self.assertEqual(len(report["unresolved_calls"]), 1)

    def test_unsupported_rebinding_is_visible_not_a_stale_read(self):
        cases = (
            'SQL = "SELECT 1"\nasync def f(db):\n    for SQL in ["DELETE FROM agents"]:\n        await db.execute(SQL)\n',
            'async def f(db):\n    SQL = "SELECT 1;"\n    SQL += "DELETE FROM agents"\n    await db.execute(SQL)\n',
        )
        for source in cases:
            with self.subTest(source=source):
                report = self.report(source)
                self.assertEqual(report["unmarked"], 0)
                self.assertEqual(len(report["unresolved_calls"]), 1)
        report = self.report(
            'SQL = "DELETE FROM agents"\nasync def f(db):\n    await db.execute(SQL)\n'
        )
        self.assertEqual(report["unmarked"], 1)
        self.assertEqual(report["unresolved_calls"], [])

    def test_unsupported_lexical_scopes_do_not_use_outer_read_literals(self):
        cases = (
            'SQL = "SELECT 1"\nrun = lambda SQL: db.execute(SQL)\nrun("DELETE FROM agents")\n',
            'SQL = "SELECT 1"\nasync def f(db):\n    match "DELETE FROM agents":\n        case SQL:\n            await db.execute(SQL)\n',
            'SQL = "SELECT 1"\nclass World:\n    SQL = "DELETE FROM agents"\n    result = db.execute(SQL)\n',
            'SQL = "SELECT 1"\ndef outer():\n    SQL = "DELETE FROM agents"\n    async def inner(db):\n        await db.execute(SQL)\n',
        )
        for source in cases:
            with self.subTest(source=source):
                report = self.report(source)
                self.assertEqual(report["unmarked"], 0)
                self.assertEqual(len(report["unresolved_calls"]), 1)
                result = self.run_check()
                self.assertEqual(result.returncode, 1)
                self.assertIn("nonliteral calls 1 > 0", result.stdout)
        report = self.report(
            'SQL = "DELETE FROM agents"\nasync def f(db):\n    await db.execute(SQL)\n'
        )
        self.assertEqual(report["unmarked"], 1)
        self.assertEqual(report["unresolved_calls"], [])

    def test_late_bound_free_names_remain_budgeted(self):
        cases = {
            "nested function": (
                'def outer(db):\n    SQL = "SELECT 1"\n    def inner():\n'
                '        db.execute(SQL)\n    SQL = "DELETE FROM agents"\n    inner()\n'
            ),
            "module global": (
                'SQL = "SELECT 1"\ndef run(db):\n    db.execute(SQL)\n'
                'SQL = "DELETE FROM agents"\nrun(db)\n'
            ),
        }
        for name, source in cases.items():
            with self.subTest(binding=name):
                report = self.report(source)
                self.assertEqual(report["unmarked"], 0)
                self.assertEqual(len(report["unresolved_calls"]), 1)
                result = self.run_check()
                self.assertEqual(result.returncode, 1)
                self.assertIn("nonliteral calls 1 > 0", result.stdout)
        report = self.report(
            'SQL = "DELETE FROM agents"\ndef run(db):\n    db.execute(SQL)\n'
        )
        self.assertEqual(report["unmarked"], 1)
        self.assertEqual(report["unresolved_calls"], [])

    def test_nine_non_simple_binding_forms_never_hide_writes(self):
        cases = {
            "lambda": ('sql="SELECT 1"\nf=lambda sql: db.execute(sql)\n', 0, 1),
            "class does not leak": (
                'sql="DELETE FROM agents"\nclass World:\n    sql="SELECT 1"\ndef f(db):\n    db.execute(sql)\n',
                1,
                0,
            ),
            "method does not inherit class": (
                'sql="DELETE FROM agents"\nclass World:\n    sql="SELECT 1"\n    def f(self, db):\n        db.execute(sql)\n',
                0,
                1,
            ),
            "match capture": (
                'sql="SELECT 1"\ndef f(db, value):\n    match value:\n        case str() as sql:\n            db.execute(sql)\n',
                0,
                1,
            ),
            "unpacking": (
                'sql="SELECT 1"\ndef f(db, pair):\n    sql, other=pair\n    db.execute(sql)\n',
                0,
                1,
            ),
            "while": (
                'sql="SELECT 1"\ndef f(db, c):\n    while c:\n        db.execute(sql)\n        sql="DELETE FROM agents"\n',
                0,
                1,
            ),
            "with as": (
                'sql="SELECT 1"\ndef f(db, cm):\n    with cm as sql:\n        db.execute(sql)\n',
                0,
                1,
            ),
            "walrus": (
                'sql="SELECT 1"\ndef f(db, g):\n    if (sql := g()):\n        db.execute(sql)\n',
                0,
                1,
            ),
            "except as": (
                'sql="SELECT 1"\ndef f(db):\n    try:\n        raise Exception()\n    except Exception as sql:\n        db.execute(sql)\n',
                0,
                1,
            ),
        }
        for name, (source, writes, dynamic) in cases.items():
            with self.subTest(binding=name):
                report = self.report(source)
                self.assertEqual(report["unmarked"], writes)
                self.assertEqual(len(report["unresolved_calls"]), dynamic)
                self.assertEqual(self.run_check().returncode, 1)

    def test_ratchet_requires_lowering_stale_and_deleted_allowances(self):
        self.write(
            "tools/product-table-write-ceilings.json",
            '{"schema_version":1,"nonliteral_files":{},"files":{"server/tests/test_world.py":2}}',
        )
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "reviewed debt",
        )
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.write(
            "server/tests/test_world.py",
            'async def f(db):\n    await db.execute("DELETE FROM agents")\n',
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("lower server/tests/test_world.py to 1", result.stdout)
        self.write(
            "tools/product-table-write-ceilings.json",
            '{"schema_version":1,"nonliteral_files":{},"files":{"server/tests/test_world.py":1}}',
        )
        self.assertEqual(self.run_check().returncode, 0)
        (self.root / "server/tests/test_world.py").unlink()
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("lower server/tests/test_world.py to 0", result.stdout)
        self.write(
            "tools/product-table-write-ceilings.json",
            '{"schema_version":1,"nonliteral_files":{},"files":{}}',
        )
        self.assertEqual(self.run_check().returncode, 0)

    def test_nonliteral_budget_is_reviewed_and_ratchets_after_resolution(self):
        self.write(
            "tools/product-table-write-ceilings.json",
            '{"schema_version":1,"nonliteral_files":{"server/tests/test_world.py":1},"files":{}}',
        )
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "reviewed nonliteral debt",
        )
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.write(
            "server/tests/test_world.py",
            "async def f(db, query):\n    await db.execute(query)\n",
        )
        self.assertEqual(self.run_check().returncode, 0)
        self.write(
            "server/tests/test_world.py",
            'async def f(db):\n    await db.execute("SELECT 1")\n',
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "nonliteral calls: lower server/tests/test_world.py to 0", result.stdout
        )
        self.write(
            "tools/product-table-write-ceilings.json",
            '{"schema_version":1,"nonliteral_files":{},"files":{}}',
        )
        self.assertEqual(self.run_check().returncode, 0)
        self.write(
            "server/tests/test_new.py",
            "async def f(db, query):\n    await db.execute(query)\n",
        )
        self.write(
            "tools/product-table-write-ceilings.json",
            '{"schema_version":1,"nonliteral_files":{"server/tests/test_new.py":1},"files":{}}',
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("ceiling 1 > reviewed 0", result.stdout)

    def test_nonliteral_new_file_refuses_and_trailing_marker_does_not_exempt(self):
        self.write(
            "server/tests/test_world.py",
            "async def f(db, query):\n    await db.execute(query)\n",
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("nonliteral calls 1 > 0", result.stdout)
        report = self.report(
            'async def f(db):\n    x = 1  # unreachable-state: corrupt row\n    await db.execute("DELETE FROM agents")\n'
        )
        self.assertEqual((report["unmarked"], report["marked"]), (1, 0))

    def test_marker_alone_cannot_admit_a_new_file(self):
        self.write(
            "server/tests/test_new.py",
            'async def f(db):\n    # unreachable-state: corrupt historical agent\n    await db.execute("INSERT INTO agents VALUES (1)")\n',
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("test_new.py: marked writes 1 > 0", result.stdout)

    def test_marked_allowance_ratchets_and_new_files_start_at_zero(self):
        path = "server/tests/test_world.py"
        statement = '    # unreachable-state: corrupt historical agent\n    await db.execute("DELETE FROM agents")\n'
        budget = {
            "schema_version": 1,
            "files": {},
            "nonliteral_files": {},
            "marked_files": {path: 2},
        }
        self.write(path, "async def f(db):\n" + statement * 2)
        self.write("tools/product-table-write-ceilings.json", json.dumps(budget))
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "reviewed historical exceptions",
        )
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.write(path, "async def f(db):\n" + statement)
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "marked writes: lower server/tests/test_world.py to 1", result.stdout
        )
        budget["marked_files"][path] = 1
        self.write("tools/product-table-write-ceilings.json", json.dumps(budget))
        self.assertEqual(self.run_check().returncode, 0)
        self.write(path, "async def f(db):\n" + statement * 3)
        budget["marked_files"][path] = 3
        self.write("tools/product-table-write-ceilings.json", json.dumps(budget))
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("marked writes ceiling 3 > reviewed 2", result.stdout)
        self.write(path, "async def f(db):\n" + statement)
        budget["marked_files"][path] = 1
        self.write("server/tests/test_new.py", "async def f(db):\n" + statement)
        budget["marked_files"]["server/tests/test_new.py"] = 1
        self.write("tools/product-table-write-ceilings.json", json.dumps(budget))
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "test_new.py: marked writes ceiling 1 > reviewed 0", result.stdout
        )
        (self.root / "server/tests/test_new.py").unlink()
        budget["marked_files"].pop("server/tests/test_new.py")
        (self.root / path).unlink()
        self.write("tools/product-table-write-ceilings.json", json.dumps(budget))
        self.assertIn(
            "marked writes: lower server/tests/test_world.py to 0",
            self.run_check().stdout,
        )
        budget["marked_files"].clear()
        self.write("tools/product-table-write-ceilings.json", json.dumps(budget))
        self.assertEqual(self.run_check().returncode, 0)

    def test_bootstrap_cannot_create_a_marked_allowance(self):
        self.git("rm", "tools/product-table-write-ceilings.json")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "main before the ceiling",
        )
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        path = "server/tests/test_world.py"
        self.write(
            path,
            'async def f(db):\n    # unreachable-state: corrupt historical agent\n    await db.execute("DELETE FROM agents")\n',
        )
        budget = {
            "schema_version": 1,
            "files": {},
            "nonliteral_files": {},
            "marked_files": {path: 1},
        }
        self.write("tools/product-table-write-ceilings.json", json.dumps(budget))
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("marked writes ceiling 1 > reviewed 0", result.stdout)
        self.write(
            path, 'async def f(db):\n    await db.execute("DELETE FROM agents")\n'
        )
        budget["marked_files"].clear()
        budget["files"][path] = 1
        self.write("tools/product-table-write-ceilings.json", json.dumps(budget))
        self.assertEqual(self.run_check().returncode, 0)

    def test_real_egress_seed_helper_is_scanned_and_budgeted(self):
        path = "scripts/test-egress/seed_awid_attestation_records.py"
        self.write(
            path,
            (
                CHECKER.parent / "test-egress/seed_awid_attestation_records.py"
            ).read_text(),
        )
        self.write(
            "awid/src/awid_service/migrations/002.sql",
            "CREATE TABLE team_certificates(id int);",
        )
        result = self.run_check("--report-only", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["unmarked"], 1)
        self.assertEqual(report["by_file"][path], {"marked": 0, "unmarked": 1})
        self.assertEqual(report["nonliteral_by_file"][path], 1)
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("unmarked writes 1 > 0", result.stdout)
        self.assertIn("nonliteral calls 1 > 0", result.stdout)
        self.write(path, 'async def seed(conn):\n    await conn.execute("SELECT 1")\n')
        self.assertEqual(self.run_check().returncode, 0)

    def test_parse_errors_and_empty_marker_refuse(self):
        self.write("server/tests/test_world.py", "def broken(:\n")
        self.assertEqual(self.run_check().returncode, 2)
        self.write(
            "server/tests/test_world.py",
            'async def f(db):\n    # unreachable-state:\n    await db.execute("DELETE FROM agents")\n',
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 2)
        self.assertIn("marker", result.stderr)


if __name__ == "__main__":
    unittest.main()

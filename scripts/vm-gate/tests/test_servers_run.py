"""The guest runner for `vm-gate run --project servers`, against real Git bundles and real bash.

Only `docker` is a stand-in: the registry the runner starts and removes.
"""

import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vm_gate import servers_run

STUB_DOCKER = """#!/bin/bash
printf '%s\\n' "$*" >> "$DOCKER_CALLS"
case "$1" in
  version) echo 29.9.3 ;;
  compose) echo 2.40.0 ;;
  run) [ -z "$REGISTRY_START_FAILS" ] || exit 1; echo registry-id ;;
  rm) [ -z "$REGISTRY_REMOVE_FAILS" ] || exit 1 ;;
esac
"""
ROLES = 'EXTERNAL POSTGRES ROLES: {"aweb": {"super": false}, "logs": {"super": false}, "operator": {"super": false}, "secrets": {"super": false}}'
LIFECYCLE = (
    'LIFECYCLE: {"server": "external", "rows": {"aweb": 12, "logs": 3, "secrets": 4}}'
)
D_CHECKS = [
    {
        "prefix": "EXTERNAL POSTGRES ROLES:",
        "assert": [
            {"path": "*.super", "equals": False},
            {"path": ".", "keys_include": ["operator"]},
        ],
    },
    {
        "prefix": "LIFECYCLE:",
        "assert": [
            {"path": "server", "equals": "external"},
            {"path": "rows.aweb", "greater_than": 0},
            {"path": "rows.secrets", "greater_than": 0},
            {"path": "rows.logs", "greater_than": 0},
        ],
    },
]


def git(cwd, *args):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


class ServersRun(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bundles = self.root / "bundles"
        self.bundles.mkdir()
        self.sources = {}
        for name in ("servers", "naapp"):
            repo = self.root / f"{name}-origin"
            repo.mkdir()
            git(repo, "init", "--quiet", "-b", "main")
            git(repo, "config", "user.email", "fixture@example.invalid")
            git(repo, "config", "user.name", "Fixture")
            (repo / "README").write_text(name)
            git(repo, "add", ".")
            git(repo, "commit", "--quiet", "-m", name)
            bundle = self.bundles / f"{name}.bundle"
            git(repo, "bundle", "create", str(bundle), "main")
            self.sources[name] = {
                "ref": "refs/heads/main",
                "commit": git(repo, "rev-parse", "HEAD"),
                "shipped_bundle_sha256": "sha256:"
                + hashlib.sha256(bundle.read_bytes()).hexdigest(),
            }
        stubs = self.root / "stubs"
        stubs.mkdir()
        (stubs / "docker").write_text(STUB_DOCKER)
        (stubs / "docker").chmod(0o755)
        self.calls = self.root / "docker-calls"
        environment = patch.dict(
            os.environ,
            {"PATH": f"{stubs}:{os.environ['PATH']}", "DOCKER_CALLS": str(self.calls)},
        )
        environment.start()
        self.addCleanup(environment.stop)
        self.out = self.root / "out"
        self.registry = {
            "name": "registry",
            "port": 5000,
            "image": "docker.io/library/registry@sha256:" + "a" * 64,
        }

    def run_spec(self, steps, registry=True):
        spec = {
            "sources": self.sources,
            "steps": steps,
            **({"registry": self.registry} if registry else {}),
        }
        path = self.root / "spec.json"
        path.write_text(json.dumps(spec))
        code = servers_run.main(
            [
                str(path),
                str(self.out),
                "--bundles",
                str(self.bundles),
                "--sources",
                str(self.root / "sources"),
                "--runs",
                str(self.root / "runs"),
            ]
        )
        return code, json.loads((self.out / "result.json").read_text())

    def step(self, name, command, **fields):
        return {
            "name": name,
            "user": "gateuser",
            "cwd": "servers",
            "command": command,
            "expect_exit": 0,
            **fields,
        }

    def clear_run(self):
        subprocess.run(
            [
                "rm",
                "-rf",
                str(self.out),
                str(self.root / "sources"),
                str(self.root / "runs"),
            ],
            check=True,
        )

    def d_step(self, command):
        return self.step(
            "D",
            command,
            require=[
                r"^KEY INIT:",
                r"^INSTALLED: secrets",
                r"^INSTALLED: logs",
                r"^DOWN: nothing of the project is left",
                r"^TIMINGS:",
            ],
            forbid=[r"^DOWN FAILED"],
            json=D_CHECKS,
            artifacts=["{run_dir}/compose.log"],
        )

    def d_output(
        self,
        roles=ROLES,
        lifecycle=LIFECYCLE,
        down="DOWN: nothing of the project is left",
        code=0,
    ):
        lines = [
            roles,
            "KEY INIT: ok",
            "INSTALLED: secrets from x",
            "INSTALLED: logs from y",
            lifecycle,
            down,
            'TIMINGS: {"total": 900}',
        ]
        body = "; ".join(f"echo {json.dumps(line)}" for line in lines)
        return f"mkdir -p {{run_dir}} && echo compose > {{run_dir}}/compose.log && echo secret > {{run_dir}}/world.env && {body}; exit {code}"

    def test_a_green_d_passes_every_check_and_collects_only_named_artifacts(self):
        code, result = self.run_spec([self.d_step(self.d_output())])
        self.assertEqual(code, 0, result)
        [d] = result["steps"]
        self.assertEqual(
            (d["verdict"], d["exit"], d["uid"]), ("passed", 0, os.getuid())
        )
        self.assertTrue(all(d["require"].values()) and not any(d["forbid"].values()))
        self.assertTrue(all(check["ok"] for check in d["json"].values()))
        self.assertEqual(list(d["artifacts"]), ["compose.log"])
        self.assertFalse((self.out / "artifacts/D/world.env").exists())
        self.assertEqual(
            {
                name: record["guest_commit"]
                for name, record in result["sources"].items()
            },
            {name: source["commit"] for name, source in self.sources.items()},
        )
        self.assertEqual(
            (result["registry"]["started"], result["registry"]["removed"]), (True, True)
        )
        log = Path(d["log"]).read_text().splitlines()
        self.assertTrue(
            all(
                re.match(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{4} ", line)
                for line in log
            ),
            log,
        )
        self.assertEqual(result["versions"], {"docker": "29.9.3", "compose": "2.40.0"})

    def test_a_zero_exit_with_down_failed_is_red(self):
        code, result = self.run_spec(
            [self.d_step(self.d_output(down="DOWN FAILED: see above"))]
        )
        self.assertEqual(code, 1)
        [d] = result["steps"]
        self.assertEqual((d["exit"], d["verdict"]), (0, "failed"))
        self.assertIn("forbidden line present: ^DOWN FAILED", d["reason"])

    def test_a_zero_exit_missing_required_evidence_is_red(self):
        command = self.d_output().replace('echo "TIMINGS: {\\"total\\": 900}"', "true")
        code, result = self.run_spec([self.d_step(command)])
        self.assertEqual(code, 1)
        self.assertIn("required line missing: ^TIMINGS:", result["steps"][0]["reason"])

    def test_one_superuser_role_or_one_empty_database_is_red(self):
        for roles, lifecycle, reason in (
            (
                ROLES.replace('"logs": {"super": false}', '"logs": {"super": true}'),
                LIFECYCLE,
                "EXTERNAL POSTGRES ROLES:",
            ),
            (ROLES, LIFECYCLE.replace('"logs": 3', '"logs": 0'), "LIFECYCLE:"),
            (ROLES, LIFECYCLE.replace('"external"', '"bundled"'), "LIFECYCLE:"),
            (
                ROLES.replace('"operator": {"super": false}, ', ""),
                LIFECYCLE,
                "EXTERNAL POSTGRES ROLES:",
            ),
        ):
            with self.subTest(
                reason=reason, roles=roles[:60], lifecycle=lifecycle[:60]
            ):
                self.clear_run()
                code, result = self.run_spec(
                    [self.d_step(self.d_output(roles=roles, lifecycle=lifecycle))]
                )
                self.assertEqual(code, 1)
                self.assertIn(
                    f"JSON check failed: {reason}", result["steps"][0]["reason"]
                )

    def a_and_c(
        self,
        a_command,
        b_command="mkdir -p images && echo '{\"images\": 6}' > images/release.json",
    ):
        return [
            self.step("B", b_command, files=["images/release.json"]),
            self.step(
                "A",
                a_command,
                cwd="naapp",
                expect_exit="nonzero",
                needs=["B"],
                require=[
                    r"checkout mode 700",
                    r"roles script: permission denied|missing role",
                ],
                inputs=[
                    {
                        "from": "B",
                        "path": "images/release.json",
                        "to": "images/release.json",
                    }
                ],
            ),
            self.step(
                "C",
                "echo adiw=PASS",
                cwd="naapp",
                needs=["B", "A"],
                require=[r"^adiw=PASS$"],
                inputs=[
                    {
                        "from": "B",
                        "path": "images/release.json",
                        "to": "images/release.json",
                    }
                ],
            ),
        ]

    def test_the_intended_a_failure_then_c_is_green(self):
        code, result = self.run_spec(
            self.a_and_c(
                "echo 'checkout mode 700'; echo 'roles script: permission denied'; exit 1"
            )
        )
        self.assertEqual(code, 0, result)
        self.assertEqual(
            [(s["name"], s["verdict"], s["exit"]) for s in result["steps"]],
            [("B", "passed", 0), ("A", "passed", 1), ("C", "passed", 0)],
        )
        manifest = result["steps"][0]["files"]["images/release.json"]
        self.assertEqual(
            result["steps"][2]["inputs"], {"images/release.json": manifest}
        )

    def test_an_unrelated_exit_1_at_a_is_red_and_c_does_not_run(self):
        code, result = self.run_spec(self.a_and_c("echo 'pull failed'; exit 1"))
        self.assertEqual(code, 1)
        a, c = result["steps"][1], result["steps"][2]
        self.assertEqual((a["exit"], a["verdict"]), (1, "failed"))
        self.assertIn("required line missing", a["reason"])
        self.assertEqual(c["verdict"], "unrun")

    def test_a_zero_exit_at_a_red_control_is_red(self):
        code, result = self.run_spec(
            self.a_and_c(
                "echo 'checkout mode 700'; echo 'roles script: permission denied'; exit 0"
            )
        )
        self.assertEqual(code, 1)
        self.assertIn("exit 0, expected nonzero", result["steps"][1]["reason"])

    def test_a_missing_or_changed_b_manifest_is_red(self):
        code, result = self.run_spec(self.a_and_c("exit 1", b_command="true"))
        self.assertEqual(code, 1)
        self.assertIn(
            "required file missing: images/release.json", result["steps"][0]["reason"]
        )
        self.assertEqual(
            [s["verdict"] for s in result["steps"][1:]], ["unrun", "unrun"]
        )
        self.clear_run()
        changing = self.a_and_c(
            "echo 'checkout mode 700'; echo 'missing role'; "
            "echo changed > ../servers/images/release.json; exit 1"
        )
        code, result = self.run_spec(changing)
        self.assertEqual(code, 1)
        self.assertEqual(result["steps"][1]["verdict"], "passed")
        self.assertIn("missing or changed since B ran", result["steps"][2]["reason"])

    def test_a_bundle_other_than_the_shipped_one_runs_nothing(self):
        self.sources["naapp"]["shipped_bundle_sha256"] = "sha256:" + "0" * 64
        code, result = self.run_spec([self.d_step(self.d_output())])
        self.assertEqual(code, 1)
        self.assertIn(
            "not the bundle the controller shipped", result["sources"]["naapp"]["error"]
        )
        self.assertEqual(result["steps"][0]["verdict"], "unrun")
        self.assertIsNone(result["registry"])

    def test_a_registry_left_behind_makes_green_steps_red(self):
        with patch.dict(os.environ, {"REGISTRY_REMOVE_FAILS": "1"}):
            code, result = self.run_spec([self.d_step(self.d_output())])
        self.assertEqual(code, 1)
        self.assertEqual(result["steps"][0]["verdict"], "passed")
        self.assertFalse(result["registry"]["removed"])
        calls = self.calls.read_text()
        self.assertIn(
            f"run -d --name registry -p 127.0.0.1:5000:5000 {self.registry['image']}",
            calls,
        )
        self.assertIn("rm -f registry", calls)

    def test_a_runner_failure_keeps_earlier_exits_and_removes_the_registry(self):
        broken = self.step("second", "true")
        del broken["user"]
        code, result = self.run_spec([self.step("first", "exit 0"), broken])
        self.assertEqual(code, 1)
        self.assertIn("KeyError", result["error"])
        self.assertEqual(
            [(s["name"], s["exit"]) for s in result["steps"]], [("first", 0)]
        )
        self.assertTrue(result["registry"]["removed"])
        self.assertEqual((self.out / "exit").read_text(), "1\n")


if __name__ == "__main__":
    unittest.main()

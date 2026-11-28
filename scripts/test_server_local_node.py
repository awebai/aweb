"""Real Make/npm orchestration controls; no Docker or service execution."""

from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

from test_server_local import Suite

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("channel-core", "channel", "pi-extension")


class LocalNodePreparation(unittest.TestCase):
    def fixture(self) -> Path:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "scripts").mkdir()
        for name in ("test_server_local.py", "local_suite_slots.py"):
            (root / "scripts" / name).write_bytes(
                (ROOT / "scripts" / name).read_bytes()
            )
        # Execute the committed installation/build owner with real npm and
        # dependency-free locked packages, then assert inputs at the suite boundary.
        (root / "mk").mkdir()
        (root / "mk/node.mk").write_bytes((ROOT / "mk/node.mk").read_bytes())
        (root / "Makefile").write_text(
            "include mk/node.mk\n"
            + "\n.PHONY: test-server test-awid\n"
            + "test-server:\n\t@node suite.cjs server\n"
            + "test-awid:\n\t@node suite.cjs registry\n"
        )
        for index, name in enumerate(PACKAGES):
            package = root / name
            package.mkdir()
            manifest = {
                "name": name,
                "version": "1.0.0",
                "scripts": {"build": "node build.cjs"},
            }
            (package / "package.json").write_text(json.dumps(manifest))
            (package / "package-lock.json").write_text(
                json.dumps(
                    {
                        "name": name,
                        "version": "1.0.0",
                        "lockfileVersion": 3,
                        "packages": {"": {"name": name, "version": "1.0.0"}},
                    }
                )
            )
            prerequisites = "".join(
                f"fs.readFileSync('../{prior}/dist/index.js');\n"
                for prior in PACKAGES[:index]
            )
            (package / "build.cjs").write_text(
                "const fs=require('node:fs');\n"
                + prerequisites
                + "fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/index.js','built');\n"
            )
        (root / "suite.cjs").write_text(
            "const fs=require('node:fs'); const suite=process.argv[2];\n"
            + "if(suite==='server') {\n"
            + "".join(
                f"fs.readFileSync('{name}/dist/index.js');\n" for name in PACKAGES
            )
            + "}\nfs.appendFileSync('suite-ran',suite+'\\n');\n"
        )
        return root

    def run_suites(
        self, *, root: Path, suite: Suite
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys,os;sys.path.insert(0,'scripts');import test_server_local as local;"
                "raise SystemExit(local.run_suites(suite=local.Suite(sys.argv[1]),workers=4,arguments=[],environ=dict(os.environ)))",
                suite.value,
            ],
            cwd=root,
            env=dict(
                os.environ,
                npm_config_offline="true",
                npm_config_cache=str(root / "cache"),
            ),
            text=True,
            capture_output=True,
            timeout=30,
        )

    def test_all_suites_build_locked_packages_before_server(self):
        root = self.fixture()
        locks = {
            name: (root / name / "package-lock.json").read_bytes() for name in PACKAGES
        }
        result = self.run_suites(root=root, suite=Suite.ALL)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((root / "suite-ran").read_text(), "server\nregistry\n")
        for name in PACKAGES:
            self.assertEqual(
                (root / name / "package-lock.json").read_bytes(), locks[name]
            )

    def test_failed_node_build_stops_before_server_with_action(self):
        root = self.fixture()
        (root / "channel/build.cjs").write_text("process.exit(37);\n")
        result = self.run_suites(root=root, suite=Suite.SERVER)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / "suite-ran").exists())
        self.assertIn(
            "Run make prepare-server-node, resolve its error, then rerun make test-server-local.",
            result.stderr,
        )

    def test_registry_only_does_not_prepare_node(self):
        root = self.fixture()
        result = self.run_suites(root=root, suite=Suite.REGISTRY)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((root / "suite-ran").read_text(), "registry\n")
        self.assertFalse(any((root / name / "dist").exists() for name in PACKAGES))


if __name__ == "__main__":
    unittest.main()

"""The candidate channel-version stage reads both committed manifests and refuses
when either version is unreadable or the two differ."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path("packages/channel/package.json")
PLUGIN = Path("packages/channel/.claude-plugin/plugin.json")


def stage_makefile() -> str:
    """The committed readers and recipe, without the rest of the Makefile."""
    lines = (ROOT / "Makefile").read_text().splitlines()
    readers = [
        line
        for line in lines
        if line.startswith(("CHANNEL_VERSION :=", "CHANNEL_PLUGIN_VERSION :="))
    ]
    start = lines.index("_candidate-channel-version:")
    end = lines.index("", start)
    return "\n".join(readers + lines[start:end]) + "\n"


@unittest.skipUnless(shutil.which("node"), "Node reads the manifests")
class ChannelVersionStage(unittest.TestCase):
    def run_stage(self, manifests: dict[Path, str | None]):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "Makefile").write_text(stage_makefile())
        for path, version in manifests.items():
            if version is not None:
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(json.dumps({"version": version}))
        return subprocess.run(
            ["make", "--no-print-directory", "_candidate-channel-version"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_equal_versions_pass(self):
        result = self.run_stage({PACKAGE: "1.8.3", PLUGIN: "1.8.3"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unequal_versions_fail(self):
        result = self.run_stage({PACKAGE: "1.8.3", PLUGIN: "1.8.2"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("channel package.json != plugin.json", result.stdout)

    def test_absent_manifests_fail(self):
        cases: tuple[dict[Path, str | None], ...] = (
            {PACKAGE: "1.8.3", PLUGIN: None},
            {PACKAGE: None, PLUGIN: "1.8.3"},
            {PACKAGE: None, PLUGIN: None},
        )
        for manifests in cases:
            with self.subTest(manifests=manifests):
                result = self.run_stage(manifests)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("has no readable version", result.stdout)


if __name__ == "__main__":
    unittest.main()

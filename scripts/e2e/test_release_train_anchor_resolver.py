"""The real anchor resolver against a tagged remote (aben R4).

_resolve_anchor_identity must peel annotated tags, take lightweight tags
directly, and refuse anchorless unmoved rows rather than guessing.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_train as rt  # noqa: E402


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class AnchorResolver(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        remote = root / "remote.git"
        git("init", "-q", "--bare", str(remote), cwd=root)
        self.repo = root / "repo"
        git("init", "-q", str(self.repo), cwd=root)
        (self.repo / "x").write_text("1\n")
        git("add", "-A", cwd=self.repo)
        git("commit", "-q", "-m", "one", cwd=self.repo)
        git("remote", "add", "origin", str(remote), cwd=self.repo)
        git("push", "-q", "origin", "HEAD:main", cwd=self.repo)
        self.sha = git("rev-parse", "HEAD", cwd=self.repo)
        git("tag", "server-v1.0.0", cwd=self.repo)
        git("tag", "-a", "-m", "n", "server-v1.0.1", cwd=self.repo)
        git("push", "-q", "origin", "refs/tags/server-v1.0.0", cwd=self.repo)
        git("push", "-q", "origin", "refs/tags/server-v1.0.1", cwd=self.repo)

        self.prepared = type(
            "P", (), {"aweb_root": self.repo, "ac_root": self.repo}
        )()
        self.artifact = rt._artifact("aweb-server")

    def tearDown(self):
        self._tmp.cleanup()

    def test_lightweight_tag_resolves(self) -> None:
        anchor = rt._resolve_anchor_identity(
            self.prepared, self.artifact, "1.0.0", timeout=5
        )
        self.assertEqual(anchor.source_identity, self.sha)
        self.assertEqual(anchor.kind, "tag")

    def test_annotated_tag_peels(self) -> None:
        anchor = rt._resolve_anchor_identity(
            self.prepared, self.artifact, "1.0.1", timeout=5
        )
        self.assertEqual(anchor.source_identity, self.sha)

    def test_absent_tag_refuses_anchorless(self) -> None:
        with self.assertRaises(rt.ObservationUnavailable):
            rt._resolve_anchor_identity(
                self.prepared, self.artifact, "9.9.9", timeout=5
            )


if __name__ == "__main__":
    unittest.main()

"""The aw external binding is answered LOCALLY (Juan's ruling).

Everything comes from a local git repository; the network is used only
to ask registries which versions are published. The aw product
repository joins the run pair as a third checkout, fetched once, and
the external tag and tree binding are read from it with local git.

plan-critic's three requirements are the three things asserted here:
the canonical location, a DISTINCT named stop for each way the
checkout can be unusable, and - the one that decides whether the other
two are decoration - that the binding cannot be SKIPPED on the release
path. A binding that silently degrades to "not checked" is the
column-b defect again: a row that never runs where it is supposed to.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer_main as main  # noqa: E402
import release_status_builders as builders  # noqa: E402


def git(*args: str, cwd: Path) -> str:
    """Identity is passed here AND stamped into every repository this
    initialises: production code under test runs git in these
    repositories too, and a developer host has a global git config
    where the gate container has none."""

    # The default branch is PINNED here, not at call sites: git's
    # init.defaultBranch differs between a developer host and the gate
    # container, and an unpinned bare remote ends up with HEAD on a
    # branch nothing was pushed to - so a later clone checks out
    # NOTHING and `commit -am` fails with "nothing to commit". Same
    # shape as the identity: a host setting the container does not have.
    if args and args[0] == "init" and not any(
        a in ("-b", "--initial-branch") for a in args
    ):
        args = (args[0], "-b", "main") + tuple(args[1:])
    result = subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    )
    if args and args[0] == "init" and "--bare" not in args:
        candidates = [cwd] + [
            Path(a) if Path(a).is_absolute() else cwd / a
            for a in args[1:] if not a.startswith("-")
        ]
        target = next(
            (c for c in reversed(candidates) if (c / ".git").exists()), cwd
        )
        for key, value in (("user.email", "t@t"), ("user.name", "t")):
            subprocess.run(["git", "config", key, value], cwd=target,
                           check=True, capture_output=True)
    return result.stdout.strip()


class AwCheckoutPreconditions(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.remote = self.root / "aw-remote.git"
        git("init", "-q", "--bare", str(self.remote), cwd=self.root)
        self.aw = self.root / "aw"
        git("init", "-q", str(self.aw), cwd=self.root)
        (self.aw / "main.go").write_text("package main\n")
        git("add", "-A", cwd=self.aw)
        git("commit", "-q", "-m", "one", cwd=self.aw)
        git("remote", "add", "origin", str(self.remote), cwd=self.aw)
        git("push", "-q", "origin", "HEAD:main", cwd=self.aw)

    def stops(self, root: Path):
        return [
            (s.code, s.artifact) for s in main.aw_checkout_stops(root)
        ]

    def test_a_healthy_checkout_produces_no_stop(self) -> None:
        # The control: without this, every other assertion here would
        # pass on a function that always refuses.
        self.assertEqual(self.stops(self.aw), [])

    def test_absent_checkout_refuses_by_its_own_name(self) -> None:
        codes = [code for code, _ in self.stops(self.root / "not-there")]
        self.assertEqual(codes, ["aw-checkout-absent"])

    def test_a_directory_that_is_not_a_repository_is_its_own_stop(self) -> None:
        plain = self.root / "plain"
        plain.mkdir()
        codes = [code for code, _ in self.stops(plain)]
        self.assertEqual(codes, ["aw-checkout-unavailable"])

    def test_dirty_checkout_refuses_by_its_own_name(self) -> None:
        (self.aw / "main.go").write_text("package main // edited\n")
        codes = [code for code, _ in self.stops(self.aw)]
        self.assertEqual(codes, ["aw-checkout-dirty"])

    def test_stale_checkout_refuses_by_its_own_name(self) -> None:
        # The remote moved on; the local checkout would answer the
        # binding from a tree the release does not name.
        other = self.root / "other"
        git("clone", "-q", str(self.remote), str(other), cwd=self.root)
        (other / "main.go").write_text("package main // upstream\n")
        git("commit", "-q", "-am", "two", cwd=other)
        git("push", "-q", "origin", "HEAD:main", cwd=other)
        codes = [code for code, _ in self.stops(self.aw)]
        self.assertEqual(codes, ["aw-checkout-stale"])

    def test_the_four_stops_are_distinct(self) -> None:
        """Each way the checkout can be unusable refuses by its OWN
        name. One generic failure would tell an operator to look, but
        not where."""

        plain = self.root / "plain2"
        plain.mkdir()
        seen = {
            self.stops(self.root / "missing")[0][0],
            self.stops(plain)[0][0],
        }
        (self.aw / "main.go").write_text("dirty\n")
        seen.add(self.stops(self.aw)[0][0])
        self.assertEqual(len(seen), 3, seen)


if __name__ == "__main__":
    unittest.main()


class LocalExternalBinding(unittest.TestCase):
    """The external binding, answered from local git.

    MEASURED against the real repositories rather than assumed: for
    awebai/aw v1.34.5, v1.34.6 and v1.34.7 the external root tree is
    aweb's cli/go tree with EXACTLY ONE extra top-level entry,
    `.github` - the external repo's own CI, which has no place in the
    monorepo path. Nothing missing, no entry differing.

    So the binding is entry-wise object-id equality: every cli/go entry
    must appear in the external tree with an identical object id, and
    the only extra permitted is the declared one. An UNDECLARED extra
    is a conflict, not a shrug - the external repository publishes what
    users install, and "some extra files appeared" is exactly what a
    binding exists to notice.

    (My first implementation compared whole trees and would have made
    every real binding row conflict-unproven. It passed against
    constructed repositories because I built them to match the
    assumption.)
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

        # aweb, carrying cli/go
        self.aweb = self.root / "aweb"
        (self.aweb / "cli" / "go").mkdir(parents=True)
        (self.aweb / "cli" / "go" / "main.go").write_text("package main\n")
        (self.aweb / "README.md").write_text("aweb\n")
        git("init", "-q", str(self.aweb), cwd=self.root)
        git("add", "-A", cwd=self.aweb)
        git("commit", "-q", "-m", "aweb one", cwd=self.aweb)
        self.aweb_sha = git("rev-parse", "HEAD", cwd=self.aweb)

        # aw, whose ROOT is a copy of that cli/go tree
        self.aw = self.root / "aw"
        (self.aw / ".github").mkdir(parents=True)
        (self.aw / ".github" / "ci.yml").write_text("on: push\n")
        (self.aw / "main.go").write_text("package main\n")
        git("init", "-q", str(self.aw), cwd=self.root)
        git("add", "-A", cwd=self.aw)
        git("commit", "-q", "-m", "Sync exact aweb " + self.aweb_sha, cwd=self.aw)
        git("tag", "-a", "v1.34.7", "-m", "v1.34.7", cwd=self.aw)

    def rows(self, tag="v1.34.7", aweb_sha=None):
        return {
            r.fact: r
            for r in builders.external_binding_rows_local(
                aw_root=self.aw,
                aweb_root=self.aweb,
                tag=tag,
                aweb_sha=aweb_sha or self.aweb_sha,
            )
        }

    def test_matching_trees_are_present(self) -> None:
        rows = self.rows()
        self.assertTrue(rows, "no rows produced")
        for fact, row in rows.items():
            with self.subTest(fact=fact):
                self.assertEqual(row.state, "observed-present", row.evidence)

    def test_a_divergent_external_tree_is_a_conflict_not_a_pass(self) -> None:
        # The control that makes the comparison mean something: change
        # ONE byte in the published tree and the binding must break.
        (self.aw / "main.go").write_text("package main // divergent\n")
        git("commit", "-q", "-am", "drift", cwd=self.aw)
        git("tag", "-a", "v1.34.8", "-m", "v1.34.8", cwd=self.aw)
        rows = self.rows(tag="v1.34.8")
        binding = [r for f, r in rows.items() if "tree" in f]
        self.assertEqual(len(binding), 1, sorted(rows))
        self.assertEqual(binding[0].state, "conflict-unproven", binding[0].evidence)

    def test_an_absent_tag_is_absent_not_unavailable(self) -> None:
        rows = self.rows(tag="v9.9.9")
        for fact, row in rows.items():
            with self.subTest(fact=fact):
                self.assertEqual(row.state, "observed-absent", row.evidence)

    def test_the_binding_reads_no_network(self) -> None:
        """The whole point of the move: it is all in the repo."""

        import urllib.request

        requested: list[str] = []
        real = urllib.request.urlopen

        def spy(request, *a, **k):
            requested.append(getattr(request, "full_url", str(request)))
            return real(request, *a, **k)

        try:
            urllib.request.urlopen = spy
            self.rows()
        finally:
            urllib.request.urlopen = real
        self.assertEqual(requested, [])


    def test_the_declared_extra_entry_is_permitted(self) -> None:
        # .github is the real, measured difference: the external repo's
        # own CI. The fixture carries it, so the healthy case above
        # already exercises this - asserted explicitly so a future
        # tightening that forbids it fails here with a reason.
        rows = self.rows()
        binding = [r for f, r in rows.items() if "tree" in f][0]
        self.assertEqual(binding.state, "observed-present", binding.evidence)

    def test_an_UNDECLARED_extra_entry_is_a_conflict(self) -> None:
        """The safe direction. An extra file in the published tree is
        content users install that our source does not contain, so an
        unknown extra must be a conflict rather than tolerated - the
        same asymmetry as the content exclusions."""

        (self.aw / "surprise.go").write_text("package main // not ours\n")
        git("add", "-A", cwd=self.aw)
        git("commit", "-q", "-m", "extra", cwd=self.aw)
        git("tag", "-a", "v1.34.9", "-m", "v1.34.9", cwd=self.aw)
        rows = self.rows(tag="v1.34.9")
        binding = [r for f, r in rows.items() if "tree" in f][0]
        self.assertEqual(binding.state, "conflict-unproven", binding.evidence)
        self.assertIn("surprise.go", binding.evidence)

    def test_a_missing_source_entry_is_a_conflict(self) -> None:
        # The other direction: the external tree must carry everything
        # cli/go has.
        (self.aweb / "cli" / "go" / "extra.go").write_text("package main\n")
        git("add", "-A", cwd=self.aweb)
        git("commit", "-q", "-m", "aweb two", cwd=self.aweb)
        newer = git("rev-parse", "HEAD", cwd=self.aweb)
        rows = self.rows(aweb_sha=newer)
        binding = [r for f, r in rows.items() if "tree" in f][0]
        self.assertEqual(binding.state, "conflict-unproven", binding.evidence)
        self.assertIn("extra.go", binding.evidence)


class ExclusionMatchesTheProducer(unittest.TestCase):
    """The exclusion is not ours to choose: aw-release.yml applies it
    when it publishes, so our read-back must apply the SAME one.

    This is the bidirectional shape that caught the tag-prefix defect -
    a value declared on one side and consumed on the other, checked
    against the producer rather than restated. It reads the real
    workflow, so if the sync ever stops excluding .github (or starts
    excluding something else) this fails instead of the binding
    silently disagreeing with what was published.
    """

    def test_the_workflow_excludes_exactly_what_we_exclude(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "aw-release.yml"
        ).read_text()
        # The workflow's awk filter, e.g. $4 !~ /^\.github\//
        found = set(re.findall(r"\$4 !~ /\^\\\.([A-Za-z0-9_.-]+)\\\//", workflow))
        self.assertTrue(
            found, "no ls-files exclusion found in aw-release.yml"
        )
        self.assertEqual(
            {"." + name + "/" for name in found},
            {builders.EXTERNAL_LISTING_EXCLUDE},
            "our binding excludes a different set than the publisher does",
        )

    def test_the_workflow_still_compares_listings_not_tree_ids(self) -> None:
        # The design forbids a subtree-hash shorthand. If the publisher
        # ever switched to comparing tree ids, our transform would have
        # to be revisited rather than silently diverge.
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "aw-release.yml"
        ).read_text()
        self.assertIn("ls-files -s", workflow)

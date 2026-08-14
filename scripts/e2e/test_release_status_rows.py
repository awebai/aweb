"""The status engine's row model (aben R5, design section 8).

The reviewer's pre-registered criteria are these fixtures' spine: the
four states exist because no path collapses them - UNPROVEN never
renders PRESENT, unavailability is never absence and never success, and
a monitor conclusion can never become presence evidence. Rows are
per-fact, and status language claims immutable public identity with a
source anchor, never reproduction.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_status as rs  # noqa: E402


class RowStates(unittest.TestCase):
    def test_the_four_states_are_closed(self) -> None:
        self.assertEqual(
            rs.STATES,
            ("observed-present", "observed-absent", "conflict-unproven", "unavailable"),
        )
        with self.assertRaises(rs.StatusError):
            rs.Row(fact="pypi:aweb sdist", state="probably-fine", evidence="x")

    def test_unproven_never_renders_present(self) -> None:
        # A row built from occupancy without identity evidence is
        # conflict-unproven; asking for its presence is False even though
        # the version document exists.
        row = rs.Row(
            fact="pypi:aweb file sha256",
            state="conflict-unproven",
            evidence="version document exists; identity evidence pending staged-byte gate",
        )
        self.assertFalse(row.present())
        self.assertIn("unproven", row.render().lower())
        self.assertNotIn("present", row.render().split(":")[0].lower())

    def test_unavailable_is_never_absence_and_never_success(self) -> None:
        row = rs.Row(fact="npm tarball", state="unavailable", evidence="HTTP 500")
        self.assertFalse(row.present())
        self.assertFalse(row.absent())

    def test_monitor_conclusion_is_not_a_row_state(self) -> None:
        # The typed remote-completion record cannot construct a row: the
        # factory refuses workflow conclusions as evidence of presence.
        record = rs.RemoteCompletion(
            workflow="pypi-release.yml", run_sha="a" * 40, conclusion="success"
        )
        with self.assertRaises(rs.StatusError) as caught:
            rs.Row.from_monitor(record)  # type: ignore[attr-defined]
        self.assertIn("not publication status", str(caught.exception))

    def test_status_language_claims_identity_never_reproduction(self) -> None:
        row = rs.Row(
            fact="pypi:aweb sdist aweb-1.27.2.tar.gz",
            state="observed-present",
            evidence="registry sha256 abc123; source anchor server-v1.27.2",
        )
        text = row.render()
        self.assertIn("immutable public identity", text)
        for forbidden in ("rebuilt", "reproduced", "byte-equal to a local"):
            self.assertNotIn(forbidden, text)

    def test_done_requires_every_row_present(self) -> None:
        rows = [
            rs.Row(fact="a", state="observed-present", evidence="e"),
            rs.Row(fact="b", state="observed-absent", evidence="e"),
        ]
        self.assertFalse(rs.done(rows))
        rows[1] = rs.Row(fact="b", state="observed-present", evidence="e")
        self.assertTrue(rs.done(rows))

    def test_done_refuses_unavailable_and_unproven(self) -> None:
        for state in ("unavailable", "conflict-unproven"):
            rows = [rs.Row(fact="a", state=state, evidence="e")]
            self.assertFalse(rs.done(rows), state)


if __name__ == "__main__":
    unittest.main()

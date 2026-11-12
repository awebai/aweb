from pathlib import Path
import tempfile
import unittest
from vm_gate.errors import Infrastructure, Refused
from vm_gate.ledger import LedgerLease

TREE = "a" * 40
OTHER = "b" * 40


def row(tree=TREE, stage="checks", status="passed"):
    return (
        "\t".join(
            [
                tree + "-inputs",
                stage,
                status,
                "c" * 40,
                "",
                "/retained/gate.log",
                "seat",
                "start",
                "end",
                "",
            ]
        )
        + "\n"
    ).encode()


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "ledger.tsv"
        self.path.write_bytes(row(status="failed"))

    def test_failure_rows_survive_snapshot_and_append_from_another_tree(self):
        with LedgerLease(self.path, OTHER) as lease:
            before = lease.snapshot(self.root / "snapshot.tsv")
            self.assertEqual(before, row(status="failed"))
            remote = before + row(OTHER)
            self.assertEqual(lease.import_rows(before, remote), 1)
            self.assertEqual(lease.import_rows(before, remote), 0)
        self.assertEqual(self.path.read_bytes(), row(status="failed") + row(OTHER))

    def test_same_tree_conflicts_with_real_gate_flock(self):
        import fcntl

        lock = self.root / "gate-locks" / f"{TREE}.lock"
        lock.parent.mkdir()
        handle = lock.open("a")
        self.addCleanup(handle.close)
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaisesRegex(Refused, "already being gated"):
            with LedgerLease(self.path, TREE):
                pass

    def test_vm_cannot_drop_failed_snapshot_rows(self):
        with LedgerLease(self.path, TREE) as lease:
            before = lease.snapshot(self.root / "snapshot.tsv")
            with self.assertRaisesRegex(Infrastructure, "snapshot prefix"):
                lease.import_rows(before, row())
        self.assertEqual(self.path.read_bytes(), row(status="failed"))

    def test_vm_cannot_append_a_different_tree_or_partial_row(self):
        with LedgerLease(self.path, TREE) as lease:
            before = lease.snapshot(self.root / "snapshot.tsv")
            for delta in [row(OTHER), row()[:-1], b"malformed\n"]:
                with self.assertRaises(Infrastructure):
                    lease.import_rows(before, before + delta)

    def test_other_tree_append_between_snapshot_and_import_is_preserved(self):
        with LedgerLease(self.path, TREE) as lease:
            before = lease.snapshot(self.root / "snapshot.tsv")
            with self.path.open("ab") as f:
                f.write(row(OTHER))
            lease.import_rows(before, before + row())
        self.assertEqual(self.path.read_bytes(), before + row(OTHER) + row())


if __name__ == "__main__":
    unittest.main()

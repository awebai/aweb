"""Owned wrapper selection, including the retained three-level gate chain."""

import copy
import tempfile
import unittest
from pathlib import Path

from candidate_processes import cleanup_wrapper, read_process


def retained_chain():
    # Actual make/Bash ancestry retained by the a27 live volume experiment.
    # UID/cwd/handler values are inputs from the required fresh /proc read.
    return [
        {
            "pid": 135444,
            "ppid": 3181,
            "command": "make candidate-gate ",
            "uid": 1000,
            "cwd": "/opt/vm-gate/source",
            "start_time": 1,
            "term_caught": True,
        },
        *[
            {
                "pid": pid,
                "ppid": ppid,
                "command": "bash scripts/candidate-docker-gate.sh ",
                "uid": 1000,
                "cwd": "/opt/vm-gate/source",
                "start_time": pid,
                "term_caught": pid == 156250,
            }
            for pid, ppid in [(156190, 135444), (156248, 156190), (156250, 156248)]
        ],
    ]


class ProcessTests(unittest.TestCase):
    def select(self, rows):
        return cleanup_wrapper(rows, 135444, uid=1000, cwd="/opt/vm-gate/source")

    def test_retained_three_level_chain_selects_cleanup_leaf(self):
        self.assertEqual(self.select(retained_chain())["pid"], 156250)

    def test_two_level_neighbor_remains_supported(self):
        rows = retained_chain()[:-1]
        rows[-1]["term_caught"] = True
        self.assertEqual(self.select(rows)["pid"], 156248)

    def test_non_cleanup_ancestor_does_not_replace_missing_leaf(self):
        self.assertIsNone(self.select(retained_chain()[:-1]))

    def test_unrelated_gate_is_not_selected(self):
        rows = retained_chain()
        other = dict(rows[-1], pid=999999, ppid=1)
        self.assertEqual(self.select(rows + [other])["pid"], 156250)
        self.assertIsNone(self.select([rows[0], other]))

    def test_ambiguous_branch_refuses(self):
        rows = retained_chain()
        self.assertIsNone(self.select(rows + [dict(rows[-1], pid=999999)]))

    def test_missing_ancestor_refuses(self):
        rows = retained_chain()
        self.assertIsNone(self.select([rows[0], *rows[2:]]))

    def test_exact_script_command_required(self):
        for command in [
            'bash -c "bash scripts/candidate-docker-gate.sh"',
            "bash scripts/candidate-docker-gate.sh --check-disk",
            "bash scripts/candidate-docker-gate.sh.extra",
        ]:
            rows = retained_chain()
            rows[-1]["command"] = command
            # A non-wrapper child means its ancestor is not a cleanup leaf.
            self.assertIsNone(self.select(rows))

    def test_wrong_source_uid_handler_or_process_identity_refuses(self):
        for field, value in [
            ("cwd", "/other"),
            ("uid", 0),
            ("term_caught", False),
            ("start_time", 0),
        ]:
            rows = retained_chain()
            rows[-1][field] = value
            self.assertIsNone(self.select(rows), field)

    def test_make_identity_required(self):
        for field, value in [("command", "make other"), ("cwd", "/other"), ("uid", 0)]:
            rows = retained_chain()
            rows[0][field] = value
            self.assertIsNone(self.select(rows))

    def test_invalid_pid_or_missing_identity_refuses(self):
        for field, value in [
            ("pid", 0),
            ("pid", -1),
            ("pid", True),
            ("ppid", -1),
            ("start_time", True),
        ]:
            rows = retained_chain()
            rows[-1][field] = value
            self.assertIsNone(self.select(rows))

    def test_duplicate_or_cyclic_identity_refuses(self):
        rows = retained_chain()
        self.assertIsNone(self.select(rows + [copy.deepcopy(rows[-1])]))
        rows[1]["ppid"] = rows[-1]["pid"]
        self.assertIsNone(self.select(rows))

    def test_linux_process_reader_captures_identity_and_start_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process = root / "123"
            process.mkdir()
            (process / "status").write_text(
                "PPid:\t12\nUid:\t1000 1000 1000 1000\nSigCgt:\t4000\n"
            )
            (process / "cmdline").write_bytes(
                b"bash\0scripts/candidate-docker-gate.sh\0"
            )
            (process / "cwd").symlink_to("/opt/vm-gate/source")
            # stat fields3..21 precede start_time22; command may contain spaces/parentheses.
            (process / "stat").write_text(
                "123 (a process (name)) " + ("0 " * 19) + "456\n"
            )
            row = read_process(123, root)
            self.assertEqual(row["start_time"], 456)
            self.assertEqual(row["uid"], 1000)
            self.assertEqual(row["cwd"], "/opt/vm-gate/source")
            self.assertTrue(row["term_caught"])
            (process / "stat").unlink()
            self.assertIsNone(read_process(123, root))


if __name__ == "__main__":
    unittest.main(verbosity=2)

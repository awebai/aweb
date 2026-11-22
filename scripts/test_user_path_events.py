"""The journey reads complete events from its real concurrently appended file."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

E2E = Path(__file__).resolve().parent / "e2e"
sys.path.insert(0, str(E2E))
spec = importlib.util.spec_from_file_location(
    "journey_events_under_test", E2E / "user_paths.py"
)
journey = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journey)


class UserPathEventFraming(unittest.TestCase):
    def test_wait_event_waits_for_the_writer_to_finish_its_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            expected = {"type": "awakening", "kind": "chat", "content": "reply"}
            encoded = json.dumps(expected).encode() + b"\n"
            path.write_bytes(b'{"type":"ready"}\n' + encoded[:-5])
            read_started = threading.Event()

            def complete_record():
                if not read_started.wait(5):
                    return
                with path.open("ab") as output:
                    output.write(encoded[-5:])

            def is_reply(event):
                if event["type"] == "ready":
                    read_started.set()
                return event == expected

            # Only the reader's data is needed; no CLI, service or method is replaced.
            lane = journey.Lane.__new__(journey.Lane)
            lane.actors = {"receiver": {"events": path}}
            lane.receivers = []
            writer = threading.Thread(target=complete_record)
            writer.start()
            try:
                self.assertEqual(lane.wait_event("receiver", is_reply), expected)
            finally:
                read_started.set()
                writer.join(timeout=5)
                self.assertFalse(writer.is_alive())

    def test_a_record_is_pending_until_its_newline_even_if_json_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(b'{"type":"awakening"}')
            self.assertEqual(journey.read_completed_events(path), [])
            with path.open("ab") as output:
                output.write(b"\n")
            self.assertEqual(
                journey.read_completed_events(path), [{"type": "awakening"}]
            )

    def test_failure_cleanup_releases_complete_events_and_keeps_original_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(
                b'{"type":"awakening","meta":{"message_id":"completed"}}\n'
                b'{"type":"awakening","meta":'
            )
            lane = journey.Lane.__new__(journey.Lane)
            lane.actors = {"receiver": {"events": path}}
            lane.failures = []
            lane.outcomes = []
            lane.version = "1.0.0"

            def fail_case():
                raise AssertionError("original journey assertion")

            lane.run_case("head/failed-case", fail_case)
            self.assertEqual(lane.failures[0]["error"], "original journey assertion")
            self.assertEqual(lane.outcomes[0]["status"], "FAILED")
            self.assertTrue(Path(str(path) + ".release-completed").is_file())

    def test_partial_utf8_in_pending_record_does_not_hide_complete_events(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(b'{"type":"ready"}\n{"content":"\xc3')
            self.assertEqual(journey.read_completed_events(path), [{"type": "ready"}])
            with path.open("ab") as output:
                output.write(b'\xa9"}\n')
            self.assertEqual(
                journey.read_completed_events(path),
                [{"type": "ready"}, {"content": "é"}],
            )

    def test_malformed_complete_records_refuse_with_actionable_evidence_path(self):
        for content in (b'{"type":\n', b"[]\n", b'{"content":"\xff"}\n'):
            with (
                self.subTest(content=content),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "events.jsonl"
                path.write_bytes(content)
                with self.assertRaises(ValueError) as raised:
                    journey.read_completed_events(path)
                self.assertIn(str(path), str(raised.exception))
                self.assertIn("record 1", str(raised.exception))
                self.assertIn(
                    "Inspect the retained receiver event log", str(raised.exception)
                )


if __name__ == "__main__":
    unittest.main()

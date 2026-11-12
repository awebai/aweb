"""Focused command-stream and explicit host-port controls for the OSS journey."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import json
import os
import re
import subprocess
import tempfile
import unittest


JOURNEY = Path(__file__).with_name("e2e-oss-user-journey.sh")


def function(name):
    match = re.search(rf"(?ms)^{name}\(\) \{{\n.*?^\}}", JOURNEY.read_text())
    if match is None:
        raise AssertionError(f"journey function {name} is missing")
    return match.group()


class CommandCaptureTests(unittest.TestCase):
    def capture(self, status=0):
        with tempfile.TemporaryDirectory() as directory:
            script = "\n".join([
                "set -euo pipefail", "pass=0; fail=0",
                function("assert_eq"), function("capture_success"),
                "child() {",
                "  printf 'called\\n' >>\"$1/calls\"",
                "  printf '%s' '{\"messages\":[{\"body\":\"delivered\"}]}'",
                "  printf '%s\\n' 'service temporarily unavailable, retrying 1/3 (GET /v1/messages/inbox)' >&2",
                f"  return {status}", "}",
                'capture_success captured inbox child "$1"',
                'printf "%s" "$captured" >"$1/captured"',
                'printf "%s" "$fail" >"$1/failures"',
            ])
            result = subprocess.run(["bash", "-c", script, "capture-test", directory],
                                    capture_output=True, text=True, check=True)
            root = Path(directory)
            return result, (root / "captured").read_text(), (root / "failures").read_text(), (root / "calls").read_text()

    def test_success_keeps_json_separate_from_legitimate_stderr_diagnostic(self):
        result, captured, failures, calls = self.capture()
        self.assertEqual(captured, '{"messages":[{"body":"delivered"}]}',
                         "successful CLI stderr contaminated the JSON consumed by the journey")
        self.assertIn("service temporarily unavailable", result.stderr)
        self.assertEqual(failures, "0")
        self.assertEqual(calls, "called\n", "capture must not retry the command")

    def test_nonzero_command_still_fails_and_discards_stdout(self):
        result, captured, failures, calls = self.capture(status=1)
        self.assertEqual(captured, "")
        self.assertEqual(failures, "1")
        self.assertIn("FAIL: inbox exit", result.stdout)
        self.assertIn("service temporarily unavailable", result.stderr)
        self.assertEqual(calls, "called\n")


class InboxParsingTests(unittest.TestCase):
    def parse(self, inbox):
        assignment = next(line for line in JOURNEY.read_text().splitlines()
                          if line.startswith('alice_join_message='))
        return subprocess.run(["bash", "-ec", assignment + '\nprintf "%s" "$alice_join_message"'],
                              env={**os.environ, "alice_join_inbox": inbox},
                              capture_output=True, text=True)

    def test_malformed_json_exposes_the_parse_failure(self):
        result = self.parse('diagnostic\n{"messages":[]}')
        self.assertNotEqual(result.returncode, 0, "inbox JSON errors must not become an empty message")
        self.assertIn("JSONDecodeError", result.stderr)

    def test_valid_inbox_without_the_message_still_reaches_the_body_assertion(self):
        result = self.parse('{"messages":[],"has_more":false}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")


class MailRefusalTraceTests(unittest.TestCase):
    """Real global-member client traces, consumed by Phase 12e's exact check.

    The HTTP fixture injects a transient fault; it is not a server/load repro.
    """

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.client = Path(cls.temp.name) / "mail-trace"
        subprocess.run([
            "go", "build", "-o", str(cls.client),
            str(JOURNEY.parent / "e2e/fixtures/mail-continuation-trace.go"),
        ], cwd=JOURNEY.parent.parent / "cli/go", check=True, capture_output=True)

    def capture(self, alias, conversation, statuses, lookup_status=200):
        posts = []
        remaining = list(statuses)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, status, body, content_type="application/json"):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path.startswith("/v1/conversations?"):
                    self.respond(lookup_status, b'{"conversations":[]}')
                elif self.path.startswith("/v1/messages/conversations/"):
                    self.respond(404, b'{"detail":"Not found"}')
                else:
                    # Server discovery's unadvertised-health neighbor.
                    self.respond(404, b'{"detail":"Not found"}')

            def do_POST(self):
                posts.append((self.path, json.loads(self.rfile.read(
                    int(self.headers["Content-Length"])))))
                status = remaining.pop(0)
                if status is None:
                    self.close_connection = True  # EOF before any HTTP response.
                    return
                if status == "html503":
                    self.respond(503, b"<html><body>Service unavailable</body></html>", "text/html")
                    return
                body = (b'{"detail":{"code":"database_unavailable","retryable":true}}'
                        if status == 503 else b'{"detail":"Not found"}')
                self.respond(status, body)

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}"
                result = subprocess.run([str(self.client), url, alias, conversation],
                                        capture_output=True, check=True, timeout=15)
            finally:
                server.shutdown()
                thread.join()
        self.assertFalse(remaining)
        self.assertEqual(len(posts), len(statuses))
        for path, body in posts:
            self.assertEqual(path, "/v1/messages")
            self.assertEqual(body["conversation_id"], conversation)
            self.assertTrue(body["message_id"])
            self.assertFalse(body.get("new_conversation", False))
            self.assertTrue(body["from_did"].startswith("did:key:"))
            self.assertTrue(body["signature"])
        self.assertTrue(all(body == posts[0][1] for _, body in posts))
        # Both fixtures are compared as observations of the same service URL.
        return result.stderr.replace(url.encode(), b"http://aweb.test")

    def compare(self, hidden, missing):
        source = JOURNEY.read_text()
        start = source.index("from pathlib import Path\nimport sys", source.index("# Compare the actual POST responses"))
        checker = source[start:source.index("\nPY\n", start)]
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("hidden", "missing")]
            for path, trace in zip(paths, (hidden, missing)):
                path.write_bytes(trace)
            return subprocess.run(["python3", "-", "http://aweb.test/v1/messages", *map(str, paths)],
                                  input=checker.encode(), capture_output=True)

    def test_global_continuation_refusals_match_without_retry(self):
        hidden = self.capture("carol", "11111111-1111-4111-8111-111111111111", [404])
        missing = self.capture("alice", "99999999-9999-4999-8999-999999999999", [404])
        result = self.compare(hidden, missing)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_exhausted_lookup_refuses_before_any_mail_post(self):
        hidden = self.capture("carol", "11111111-1111-4111-8111-111111111111", [], lookup_status=503)
        self.assertNotIn(b"AW TRACE request: POST ", hidden)
        self.assertIn(b"retrying 3/3 (GET /v1/conversations?", hidden)
        missing = self.capture("alice", "99999999-9999-4999-8999-999999999999", [404])
        result = self.compare(hidden, missing)
        self.assertNotEqual(result.returncode, 0, "a lookup refusal proves no mail POST refusal")

    def test_global_continuation_refusals_match_after_transient_post_retry(self):
        hidden = self.capture("carol", "11111111-1111-4111-8111-111111111111", [503, 404])
        missing = self.capture("alice", "99999999-9999-4999-8999-999999999999", [404])
        self.assertIn(b"retrying 1/3 (POST /v1/messages)", hidden)
        result = self.compare(hidden, missing)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_transport_retry_still_compares_the_final_refusal(self):
        hidden = self.capture("carol", "11111111-1111-4111-8111-111111111111", [None, 404])
        missing = self.capture("alice", "99999999-9999-4999-8999-999999999999", [404])
        self.assertIn(b"retrying 1/3 (POST /v1/messages)", hidden)
        result = self.compare(hidden, missing)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_sanitized_html_retry_does_not_need_a_raw_body_length(self):
        hidden = self.capture("carol", "11111111-1111-4111-8111-111111111111", ["html503", 404])
        missing = self.capture("alice", "99999999-9999-4999-8999-999999999999", [404])
        result = self.compare(hidden, missing)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_exhausted_post_retries_remain_a_failure(self):
        hidden = self.capture("carol", "11111111-1111-4111-8111-111111111111", [503] * 4)
        missing = self.capture("alice", "99999999-9999-4999-8999-999999999999", [404])
        result = self.compare(hidden, missing)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"final mail POST HTTP 503", result.stderr)

    def test_bad_retry_and_malformed_traces_are_not_discarded(self):
        hidden = self.capture("carol", "11111111-1111-4111-8111-111111111111", [503, 404])
        missing = self.capture("alice", "99999999-9999-4999-8999-999999999999", [404])
        retry_notice = b"service temporarily unavailable, retrying 1/3 (POST /v1/messages)\n"
        cases = {
            "non-retryable earlier response": hidden.replace(b"AW TRACE response: HTTP 503", b"AW TRACE response: HTTP 403"),
            "missing retry notice": hidden.replace(retry_notice, b""),
            "partial earlier response": hidden.replace(b"AW TRACE response: HTTP 503\n", b""),
            "incomplete final body": hidden.replace(b'AW TRACE response body: {"detail":"Not found"}', b'AW TRACE response body: {"detail":'),
            "missing final response": hidden[:hidden.rindex(b"AW TRACE response: HTTP 404")],
            "different final bytes": hidden.replace(b'{"detail":"Not found"}', b'{"detail":"NoT found"}'),
            "different content type": hidden.replace(b"Content-Type: application/json", b"Content-Type: application/problem+json"),
        }
        for name, trace in cases.items():
            with self.subTest(name=name):
                self.assertNotEqual(self.compare(trace, missing).returncode, 0)


class ServicePortTests(unittest.TestCase):
    def test_explicit_ports_are_preserved_without_a_docker_allocation(self):
        script = "\n".join([
            "set -euo pipefail",
            function("allocate_service_ports"),
            'docker() { echo "unexpected docker call" >&2; exit 1; }',
            'AWEB_PORT=18100; AWID_PORT=18110; PORT_ALLOCATOR=""',
            'allocate_service_ports',
            'printf "%s %s" "$AWEB_PORT" "$AWID_PORT"',
        ])
        result = subprocess.run(["bash", "-c", script], capture_output=True,
                                text=True, check=True, env={**os.environ, "CANDIDATE_RUNNER_NAME": ""})
        self.assertEqual(result.stdout, "18100 18110")


if __name__ == "__main__":
    unittest.main()

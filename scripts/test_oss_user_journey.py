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



# A Docker daemon with its own filesystem. Inside the candidate runner the CLI
# talks to the host daemon, which resolves a bind source on its own host: only
# the run-owned bind root, mounted into the runner at the same path, is there.
# A missing bind source is created as an empty directory, as Docker does. The
# ownership tools record what they were asked to do: the controls run unprivileged.
DAEMON_STUB = r"""
docker() {
  local src="" script=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -v) src="${2%%:*}"; shift 2 ;;
      -c) script="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  printf '%s\n' "$src" >>"$CALLS"
  local view="$DAEMON_ROOT$src"
  mkdir -p "$view"
  KEYS_VIEW="$view" PATH="$FAKE_BIN:$PATH" sh -c "${script//\/keys/$view}"
}
"""

FAKE_TOOLS = {
    "chown": r"""#!/usr/bin/env bash
owner="$1"; shift; status=0
for path in "$@"; do
  if [[ -n "${FAKE_CHOWN_REFUSE:-}" ]]; then
    echo "chown: ${path/#$KEYS_VIEW//keys}: Operation not permitted" >&2; status=1
  elif [[ -e "$path" ]]; then
    printf 'owner %s %s\n' "${path/#$KEYS_VIEW//keys}" "$owner" >>"$LEDGER"
  else
    echo "chown: ${path/#$KEYS_VIEW//keys}: No such file or directory" >&2; status=1
  fi
done
exit "$status"
""",
    "chmod": r"""#!/usr/bin/env bash
mode="$1"; shift; status=0
for path in "$@"; do
  if [[ -e "$path" ]]; then
    printf 'mode %s %s\n' "${path/#$KEYS_VIEW//keys}" "${mode#0}" >>"$LEDGER"
  else
    echo "chmod: ${path/#$KEYS_VIEW//keys}: No such file or directory" >&2; status=1
  fi
done
exit "$status"
""",
    "stat": r"""#!/usr/bin/env bash
shift 2
for path in "$@"; do
  name="${path/#$KEYS_VIEW//keys}"
  owner="$(awk -v n="$name" '$1 == "owner" && $2 == n {v = $3} END {print v}' "$LEDGER")"
  mode="$(awk -v n="$name" '$1 == "mode" && $2 == n {v = $3} END {print v}' "$LEDGER")"
  printf '%s %s %s\n' "$name" "$owner" "$mode"
done
""",
}


class CustomerSecretsStagingTests(unittest.TestCase):
    """Phase 11b2 stages the customer server's credentials where the daemon sees them."""

    def stage(self, bind_root=True, env_bind_root=None, remove_key=False, refuse_chown=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            private_tmp, bind, daemon, fake_bin = (root / "runner-tmp", root / "docker-bind",
                                                   root / "daemon", root / "bin")
            for path in (private_tmp, bind, daemon, fake_bin):
                path.mkdir()
            # The gate mounts the bind root into the runner at its own path.
            (daemon / bind.relative_to("/")).parent.mkdir(parents=True)
            (daemon / bind.relative_to("/")).symlink_to(bind)
            for name, body in FAKE_TOOLS.items():
                (fake_bin / name).write_text(body)
                (fake_bin / name).chmod(0o755)
            ledger, calls = root / "ledger", root / "calls"
            ledger.touch(); calls.touch()
            script = "\n".join([
                "set -euo pipefail", "pass=0; fail=0",
                function("canonicalize_dir"), function("journey_temp_root"),
                function("assert_eq"), function("capture_success"), function("run_success"),
                function("write_staged_file"), function("stage_customer_secrets"),
                DAEMON_STUB,
                'TEMP_ROOT="$(journey_temp_root)"',
                'E2E_ROOT="$(mktemp -d "$TEMP_ROOT/aw-e2e.XXXXXX")"',
                'CUSTOMER_IDENTITY_DIR="$E2E_ROOT/customer-server-home/identity"',
                'CUSTOMER_SECRETS_DIR="$E2E_ROOT/customer-server/secrets"',
                'CUSTOMER_KEYS_DIR="$CUSTOMER_SECRETS_DIR/aweb"',
                'mkdir -p "$CUSTOMER_IDENTITY_DIR/.aw" "$CUSTOMER_KEYS_DIR"',
                "printf 'test-only member key' >\"$CUSTOMER_IDENTITY_DIR/.aw/signing.key\"",
                'chmod 0600 "$CUSTOMER_IDENTITY_DIR/.aw/signing.key"',
                '[[ -z "$REMOVE_KEY" ]] || rm "$CUSTOMER_IDENTITY_DIR/.aw/signing.key"',
                'if stage_customer_secrets; then staged=yes; else staged=no; fi',
                'printf "staged=%s fail=%s root=%s\\n" "$staged" "$fail" "$E2E_ROOT"',
            ])
            env = {**os.environ, "TMPDIR": str(private_tmp), "DAEMON_ROOT": str(daemon),
                   "FAKE_BIN": str(fake_bin), "LEDGER": str(ledger), "CALLS": str(calls),
                   "REMOVE_KEY": "1" if remove_key else ""}
            env.pop("AWEB_DOCKER_BIND_ROOT", None)
            env.pop("FAKE_CHOWN_REFUSE", None)
            if refuse_chown:
                env["FAKE_CHOWN_REFUSE"] = "1"
            if bind_root:
                env["AWEB_DOCKER_BIND_ROOT"] = env_bind_root or str(bind)
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
            daemon_views = sorted(str(p.relative_to(daemon)) for p in daemon.rglob("aweb")
                                  if p.is_dir() and not p.is_symlink())
            return dict(result=result, ledger=ledger.read_text(), calls=calls.read_text(),
                        bind=bind, private_tmp=private_tmp, daemon_views=daemon_views)

    def test_runner_private_temp_root_is_invisible_to_the_daemon(self):
        # The gate-13 mechanism: the runner wrote the files under its own /tmp,
        # and the daemon bound an empty directory it created for that path.
        run = self.stage(bind_root=False)
        out = run["result"].stdout
        self.assertEqual(run["result"].returncode, 0, run["result"].stderr)
        self.assertIn("staged=no fail=1", out)
        self.assertIn("FAIL: customer secrets ownership exit", out)
        self.assertIn("missing in the daemon view of the customer secrets: customerteam.key", out)
        self.assertEqual(run["ledger"], "", "nothing may be chowned that the daemon cannot see")
        self.assertEqual(len(run["daemon_views"]), 1, run["daemon_views"])
        self.assertIn(str(run["private_tmp"]).lstrip("/"), run["daemon_views"][0])

    def test_bind_root_makes_the_secrets_visible_and_owned_by_the_image_user(self):
        run = self.stage()
        out = run["result"].stdout
        self.assertEqual(run["result"].returncode, 0, run["result"].stderr)
        self.assertIn("staged=yes fail=0", out)
        self.assertIn(f"root={run['bind']}/aw-e2e.", out)
        self.assertIn("PASS: customer secrets are owned by the image user", out)
        self.assertEqual(sorted(run["ledger"].splitlines()), sorted([
            "owner /keys/customerteam.key 1001:1001", "owner /keys/database-url 1001:1001",
            "mode /keys/customerteam.key 400", "mode /keys/database-url 400"]))
        self.assertEqual(run["daemon_views"], [], "the daemon must not create a bind source")

    def test_missing_member_key_is_a_named_failure_before_any_container(self):
        run = self.stage(remove_key=True)
        out = run["result"].stdout
        self.assertEqual(run["result"].returncode, 0, run["result"].stderr)
        self.assertIn("staged=no fail=1", out)
        self.assertIn("FAIL: customer server key staged exit", out)
        self.assertEqual(run["calls"], "", "no container runs after a staging failure")

    def test_refused_ownership_change_is_a_named_failure(self):
        run = self.stage(refuse_chown=True)
        out = run["result"].stdout
        self.assertEqual(run["result"].returncode, 0, run["result"].stderr)
        self.assertIn("staged=no", out)
        self.assertIn("FAIL: customer secrets ownership exit", out)
        self.assertIn("Operation not permitted", run["result"].stderr)

    def test_bind_root_must_be_an_existing_absolute_directory(self):
        for value in ("relative/docker-bind", "/nonexistent-aweb-bind-root"):
            with self.subTest(value=value):
                run = self.stage(env_bind_root=value)
                self.assertNotEqual(run["result"].returncode, 0)
                self.assertIn("AWEB_DOCKER_BIND_ROOT must be an existing absolute directory",
                              run["result"].stderr)

    def test_journey_allocates_its_root_and_stages_through_the_checked_functions(self):
        text = JOURNEY.read_text()
        self.assertIn('TEMP_ROOT="$(journey_temp_root)" || exit 2', text)
        self.assertIn("stage_customer_secrets || exit 1", text)
        self.assertEqual(text.count('-v "$CUSTOMER_KEYS_DIR:/keys"'), 1,
                         "the keys directory is bound only by stage_customer_secrets")
        self.assertIn('-v "$CUSTOMER_KEYS_DIR:/keys"', function("stage_customer_secrets"))


if __name__ == "__main__":
    unittest.main()

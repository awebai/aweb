"""The real command stack's stdin commands, without starting any service.

Run with the server project's environment, which the fixture itself uses:
uv run --offline --frozen --project server python -P <this file>
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.append(str(Path(__file__).resolve().parent))

from aweb_fixture import apply_command  # noqa: E402
from aweb_naapp_testing.network import DnsServer  # noqa: E402
from awid.ratelimit import MemoryFixedWindowRateLimiter  # noqa: E402

CONTROLLER = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


class Registry:
    """Only the app state the commands touch."""

    def __init__(self):
        self.state = SimpleNamespace(
            awid_public_origins=("http://127.0.0.1:1",),
            rate_limiter=MemoryFixedWindowRateLimiter(),
        )


def run(zone, registry, command):
    line = command if isinstance(command, str) else json.dumps(command)
    return apply_command(zone, registry, line)


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.zone, self.registry = DnsServer(), Registry()
        self.origins = self.registry.state.awid_public_origins
        self.limiter = self.registry.state.rate_limiter

    def assertRefusedWithoutEffect(self, command, error):
        self.assertEqual(run(self.zone, self.registry, command), error)
        self.assertEqual(self.zone.records, {})
        self.assertEqual(self.registry.state.awid_public_origins, self.origins)
        self.assertIs(self.registry.state.rate_limiter, self.limiter)

    def test_zone_publishes_one_record(self):
        reply = run(
            self.zone,
            self.registry,
            {"id": 7, "zone": {"domain": "a.test", "controller": CONTROLLER}},
        )
        self.assertEqual(reply, {"id": 7, "ok": True})
        self.assertEqual(
            self.zone.records,
            {("_awid.a.test", "TXT"): [f'"awid=v1; controller={CONTROLLER};"']},
        )

    def test_malformed_commands_are_refused_without_effect(self):
        zone = {"domain": "a.test", "controller": CONTROLLER}
        fields = "Send {'zone': {'domain': <name>, 'controller': <did:key>}}."
        for command, error in [
            (
                "{not json",
                {"error": "command is not JSON. Send one JSON object per line."},
            ),
            (
                {"id": True, "zone": zone},
                {
                    "error": "command needs an integer id. Give every command its own id."
                },
            ),
            (
                {"id": "1", "zone": zone},
                {
                    "error": "command needs an integer id. Give every command its own id."
                },
            ),
            (
                [1],
                {
                    "error": "command needs an integer id. Give every command its own id."
                },
            ),
            (
                {"id": 1},
                {
                    "id": 1,
                    "error": "command names no single known operation. Send exactly one of zone, public_origin or reset_rate_limits.",
                },
            ),
            (
                {"id": 1, "zone": zone, "reset_rate_limits": {}},
                {
                    "id": 1,
                    "error": "command names no single known operation. Send exactly one of zone, public_origin or reset_rate_limits.",
                },
            ),
            (
                {"id": 1, "zone": {"domain": "a.test"}},
                {
                    "id": 1,
                    "error": "zone needs exactly domain and controller. " + fields,
                },
            ),
            (
                {"id": 1, "zone": {**zone, "registry": "x"}},
                {
                    "id": 1,
                    "error": "zone needs exactly domain and controller. " + fields,
                },
            ),
            (
                {"id": 1, "zone": {"domain": None, "controller": CONTROLLER}},
                {"id": 1, "error": "zone domain is not a string. " + fields},
            ),
            (
                {"id": 1, "zone": {"domain": "A.test", "controller": CONTROLLER}},
                {
                    "id": 1,
                    "error": "zone domain is not a canonical DNS name. Send lowercase ASCII labels with no trailing dot.",
                },
            ),
            (
                {"id": 1, "zone": {"domain": "a.test.", "controller": CONTROLLER}},
                {
                    "id": 1,
                    "error": "zone domain is not a canonical DNS name. Send lowercase ASCII labels with no trailing dot.",
                },
            ),
            (
                {"id": 1, "zone": {"domain": "a.test", "controller": "did:key:znot"}},
                {
                    "id": 1,
                    "error": "zone controller is not an Ed25519 did:key. Send the namespace controller's did:key.",
                },
            ),
            (
                {"id": 1, "zone": {"domain": "a.test", "controller": None}},
                {
                    "id": 1,
                    "error": "zone controller is not an Ed25519 did:key. Send the namespace controller's did:key.",
                },
            ),
            (
                {"id": 1, "public_origin": "https://registry.example"},
                {
                    "id": 1,
                    "error": "public_origin is not a canonical http://127.0.0.1 origin. Send the front's origin as http://127.0.0.1:<port>.",
                },
            ),
            (
                {"id": 1, "public_origin": "http://127.0.0.1:8080/path"},
                {
                    "id": 1,
                    "error": "public_origin is not a canonical http://127.0.0.1 origin. Send the front's origin as http://127.0.0.1:<port>.",
                },
            ),
            (
                {"id": 1, "public_origin": None},
                {
                    "id": 1,
                    "error": "public_origin is not a canonical http://127.0.0.1 origin. Send the front's origin as http://127.0.0.1:<port>.",
                },
            ),
            (
                {"id": 1, "reset_rate_limits": {"bucket": "all"}},
                {
                    "id": 1,
                    "error": "reset_rate_limits takes an empty object. Send {'reset_rate_limits': {}}.",
                },
            ),
        ]:
            with self.subTest(command=command):
                self.assertRefusedWithoutEffect(command, error)

    def test_duplicate_zone_keeps_the_first_record(self):
        other = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
        first = {"id": 1, "zone": {"domain": "a.test", "controller": CONTROLLER}}
        self.assertEqual(run(self.zone, self.registry, first), {"id": 1, "ok": True})
        published = dict(self.zone.records)
        reply = run(
            self.zone,
            self.registry,
            {"id": 2, "zone": {"domain": "a.test", "controller": other}},
        )
        self.assertEqual(
            reply,
            {
                "id": 2,
                "error": "zone domain is already published. Use a fresh domain for each world.",
            },
        )
        self.assertEqual(self.zone.records, published)

    def test_public_origin_and_rate_limit_reset_take_effect(self):
        reply = run(
            self.zone,
            self.registry,
            {"id": 1, "public_origin": "http://127.0.0.1:61234"},
        )
        self.assertEqual(reply, {"id": 1, "ok": True})
        self.assertEqual(
            self.registry.state.awid_public_origins,
            self.origins + ("http://127.0.0.1:61234",),
        )
        reply = run(self.zone, self.registry, {"id": 2, "reset_rate_limits": {}})
        self.assertEqual(reply, {"id": 2, "ok": True})
        self.assertIsNot(self.registry.state.rate_limiter, self.limiter)


class StackRequiresTheOptIn(unittest.TestCase):
    def test_stack_refuses_before_starting_anything(self):
        env = {k: v for k, v in os.environ.items() if k != "AWEB_TEST_SERVICES"}
        result = subprocess.run(
            [sys.executable, "-P", str(Path(__file__).resolve().parent / "aweb_fixture.py")],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            result.stderr.strip(),
            "this test needs the real service stack; run it on the gate or a dev VM "
            "(AWEB_TEST_SERVICES=1)",
        )


if __name__ == "__main__":
    unittest.main()

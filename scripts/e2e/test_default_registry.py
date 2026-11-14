"""Source-input and evidence controls; these do not qualify a native journey."""
import copy
from pathlib import Path
import tempfile
import unittest

from default_registry_client import Journey, write_zone
from lab_lifecycle import created_epoch, load_json, validate_plan
from lab_process import Containment
from registry_quota_probe import exercise


class InputControls(unittest.TestCase):
    def test_duplicate_json_is_not_an_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text('{"fixture_id":"first","fixture_id":"second"}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_json(path)

    def test_resource_plan_is_bound_to_run_source_and_listener(self):
        admission = dict(fixture_id="adaz-" + "a" * 32, provider_run_id="vm-" + "b" * 32,
                         cloud_source_sha="c" * 40, public_ipv4="8.8.8.8")
        plan = dict(schema_version=1, **{k: admission[k] for k in ("fixture_id", "provider_run_id", "cloud_source_sha")},
                    owner_label=dict(key="aweb.ac.candidate-gate", value="owned-run"),
                    runner_name="owned-run-runner", network_name="owned-network", volume_names=["owned-tls"],
                    compose_projects=["owned-project"], created_unix_seconds=1,
                    published_listener=dict(project="owned-project", service="awid", host_ip="8.8.8.8",
                                            published_port=8010, target_port=8010, protocol="tcp"))
        self.assertIs(validate_plan(plan, admission), plan)
        for key in ("fixture_id", "provider_run_id", "cloud_source_sha"):
            changed = copy.deepcopy(plan)
            changed[key] += "wrong"
            with self.assertRaises(ValueError):
                validate_plan(changed, admission)
        for field, value in (("host_ip", "127.0.0.1"), ("published_port", 443), ("project", "foreign")):
            changed = copy.deepcopy(plan)
            changed["published_listener"][field] = value
            with self.assertRaises(ValueError):
                validate_plan(changed, admission)

    def test_creation_time_needs_actual_timezone(self):
        self.assertEqual(created_epoch("1970-01-01T00:00:01Z"), 1)
        with self.assertRaises(ValueError):
            created_epoch("1970-01-01T00:00:01")

    def test_dns_regeneration_preserves_authority_and_uses_valid_serial(self):
        with tempfile.TemporaryDirectory() as directory:
            zone = Path(directory) / "authority.zone"
            write_zone(zone, "8.8.8.8", {"alice.example.com": "awid=actual-first"})
            write_zone(zone, "8.8.8.8", {"alice.example.com": "awid=actual-first", "bob.example.net": "awid=actual-second"})
            text = zone.read_text()
            self.assertIn("(2 1 1 1 1)", text)
            self.assertIn("api.awid.ai. IN A 8.8.8.8", text)
            self.assertIn('_awid.alice.example.com. IN TXT "awid=actual-first"', text)
            self.assertIn('_awid.bob.example.net. IN TXT "awid=actual-second"', text)
            self.assertEqual(zone.stat().st_mode & 0o777, 0o644)
            with self.assertRaises(ValueError):
                write_zone(zone, "8.8.8.8", {"alice.example.com": "bad\nrecord"})

    def test_customer_endpoint_flags_refuse_before_cli_invocation(self):
        journey = Journey.__new__(Journey)
        for args in (("id", "show", "--registry=https://foreign"), ("id", "create", "--skip-dns-verify")):
            with self.assertRaisesRegex(ValueError, "override"):
                journey.command("uncreated-actor", *args)

    def test_probe_invalid_inputs_refuse_before_output_or_network(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            for args in (("http://api.awid.ai", "example.com", "did:aw:test", "8.8.8.8"),
                         ("https://api.awid.ai", "bad/name", "did:aw:test", "8.8.8.8"),
                         ("https://api.awid.ai", "example.com", "did:aw:test", "127.0.0.1")):
                with self.assertRaises(ValueError):
                    exercise(*args, output)
                self.assertFalse(output.exists())

    def test_containment_identity_cannot_choose_another_cgroup(self):
        # Platform/API refusal on this host is also fail-closed. This is NOT a
        # substitute for the Linux nested-process/cgroup qualification.
        with self.assertRaises((RuntimeError, ValueError)):
            Containment("../foreign")


if __name__ == "__main__":
    unittest.main()

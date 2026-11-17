"""The deployment renders one organisation policy, including explicit off."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "render_env", ROOT / "deploy/team/render_env.py"
)
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)

BASE = {
    "team": {"id": "example:example.test"},
    "postgres": {},
    "aweb": {
        "image": "ghcr.io/awebai/aweb-server@sha256:" + "0" * 64,
        "publicOrigin": "https://aweb.example.test",
    },
    "network": {"servicesCidr": "172.31.0.0/24"},
    "compose": {"secretsDir": "/etc/aweb-secrets"},
}


class DeploymentPolicyTests(unittest.TestCase):
    def test_absent_section_renders_explicit_off_for_the_same_organisation(self):
        self.assertEqual(
            json.loads(renderer.render_human_approval(BASE)),
            {
                "organisation": "example.test",
                "human_approval": {},
            },
        )

    def test_configured_section_is_the_single_rendered_source(self):
        value = copy.deepcopy(BASE)
        value["human_approval"] = {
            "service": "https://awsign.example.test",
            "require": {"organisation.human.add": "hardware"},
        }
        result = json.loads(renderer.render_human_approval(value))
        self.assertEqual(result["human_approval"], value["human_approval"])
        self.assertEqual(result["organisation"], "example.test")
        # No component policy switch is rendered alongside the shared source.
        self.assertNotIn("HUMAN_ISSUANCE", renderer.render(value))

    def test_malformed_section_is_not_treated_as_missing(self):
        for section in (None, [], {"require": []}, {"enabled": False}):
            with self.subTest(section=section), self.assertRaises(renderer.Refused):
                renderer.render_human_approval({**BASE, "human_approval": section})


if __name__ == "__main__":
    unittest.main()

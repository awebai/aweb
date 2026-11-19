"""Database-free fixture discovery controls, using the real aweb/AWID source.

Run in the source monorepo's locked Python environment with its dependencies.
No DNS, HTTP, database, container, or identity is created by these controls.
"""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(os.environ.get("HERMES_FIXTURE_SOURCE", Path(__file__).resolve().parents[3])).resolve()
sys.path[:0] = [str(ROOT / "awid/src"), str(ROOT / "server/src")]
from aweb.federation.activation import build_federation_authority_activation
from awid.external_authority import DNSLookup

OVERLAY = Path(__file__).with_name("fixture-local-registry.compose.yml")


class DatabasePort:
    def get_manager(self, *args):
        return object()


class NoPublicTXT:
    def __init__(self):
        self.queries = []

    async def lookup_txt(self, name):
        self.queries.append(name)
        return DNSLookup("nxdomain")


class FixtureRegistryTests(unittest.IsolatedAsyncioTestCase):
    def base_env(self):
        return {"APP_ENV": "development", "AWID_REGISTRY_URL": "http://awid:8010"}

    def activation(self):
        result = build_federation_authority_activation(DatabasePort(), public_origin="http://127.0.0.1:28180")
        result.txt_resolver = NoPublicTXT()
        return result

    async def test_loopback_overlay_uses_registered_local_identity_authority(self):
        overlay = yaml.safe_load(OVERLAY.read_text())
        env = {**self.base_env(), **overlay["services"].get("aweb", {}).get("environment", {})}
        with patch.dict(os.environ, env, clear=True):
            activation = self.activation()
            authority = await activation._discover_registry_authority("hermes-acft1.test")
        self.assertEqual(authority.registry_origin, "http://awid:8010",
                         "fixture contact discovery escaped the registry where its address was claimed")
        self.assertEqual(activation.txt_resolver.queries, [])

    async def test_backend_registry_url_alone_does_not_override_public_discovery(self):
        with patch.dict(os.environ, self.base_env(), clear=True):
            authority = await self.activation()._discover_registry_authority("hermes-acft1.test")
        self.assertEqual(authority.registry_origin, "https://api.awid.ai")

    def test_explicit_fixture_registry_keeps_both_development_guards(self):
        for app_env, test in (("production", "1"), ("development", "0")):
            with (
                self.subTest(app_env=app_env, test=test),
                patch.dict(os.environ, {
                    **self.base_env(), "APP_ENV": app_env, "AWEB_FEDERATION_TEST": test,
                    "AWEB_FEDERATION_TEST_DEFAULT_REGISTRY": "1",
                }, clear=True),
                self.assertRaises(ValueError),
            ):
                self.activation()

    def test_awid_origin_guards_are_retained(self):
        env = yaml.safe_load(OVERLAY.read_text())["services"]["awid"]["environment"]
        self.assertEqual(env["APP_ENV"], "test")
        self.assertEqual(str(env["AWID_ALLOW_INSECURE_DELIVERY_ORIGIN"]).lower(), "true")

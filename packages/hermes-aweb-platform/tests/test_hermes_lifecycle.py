"""Run against a real Hermes checkout and its installed dependencies.

HERMES_AGENT_SOURCE=/path/to/hermes-agent python -m unittest discover \
    -s packages/hermes-aweb-platform/tests -p test_hermes_lifecycle.py -v
"""

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


source = os.environ.get("HERMES_AGENT_SOURCE")
if not source:
    raise unittest.SkipTest("Set HERMES_AGENT_SOURCE to a real Hermes checkout")
sys.path.insert(0, str(Path(source).resolve()))

spec = importlib.util.spec_from_file_location(
    "aweb_lifecycle_adapter", Path(__file__).resolve().parents[1] / "adapter.py"
)
adapter_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter_module)


class HermesLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_initial_and_reconnect_reach_adapter_validation(self):
        # Register with Hermes itself: this checks the real PlatformEntry kwargs too.
        from gateway.config import Platform, PlatformConfig
        from gateway.platform_registry import platform_registry
        from gateway.run_adapters import GatewayAdapterLifecycleMixin
        from hermes_cli.plugins import PluginContext, PluginManifest, PluginManager

        manager = PluginManager()
        context = PluginContext(PluginManifest(name="aweb-lifecycle-test"), manager)
        adapter_module.register(context)
        platform = Platform("aweb")
        lifecycle = GatewayAdapterLifecycleMixin()
        # The registry checks executable availability before seeing PlatformConfig.
        with (
            tempfile.TemporaryDirectory() as root,
            patch.dict(os.environ, {"AWEB_PLATFORM_AW_BIN": sys.executable}),
        ):
            # An absent workdir makes real adapter validation fail before any aw
            # subprocess starts. No gateway method or transport is substituted.
            config = PlatformConfig(extra={"workdir": str(Path(root) / "absent")})
            for reconnect in (False, True):
                with self.subTest(is_reconnect=reconnect):
                    adapter = platform_registry.create_adapter("aweb", config)
                    self.assertIsInstance(adapter, adapter_module.AwebAdapter)
                    connected = await lifecycle._connect_adapter_with_timeout(
                        adapter, platform, is_reconnect=reconnect, initial=not reconnect
                    )
                    self.assertFalse(connected)
                    self.assertEqual(adapter.fatal_error_code, "workdir_missing")
                    self.assertIsNone(adapter._stream_task)
                    await lifecycle._safe_adapter_disconnect(adapter, platform)


if __name__ == "__main__":
    unittest.main()

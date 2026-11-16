"""Exercise the requested skeleton's actual browser CDP connection, not a service fake."""

import asyncio
import unittest

from adcl6_first_path import browser_actors


class BrowserWiringTest(unittest.TestCase):
    def test_two_isolated_uv_authenticators(self):
        async def run():
            async with browser_actors() as actors:
                first, second = actors["first"], actors["second"]
                self.assertNotEqual(first.authenticator_id, second.authenticator_id)
                self.assertIsNot(first.page.context, second.page.context)
                for actor in (first, second):
                    response = await actor.cdp.send(
                        "WebAuthn.getCredentials",
                        {"authenticatorId": actor.authenticator_id},
                    )
                    self.assertEqual(response["credentials"], [])

        asyncio.run(run())

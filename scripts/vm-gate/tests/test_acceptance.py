import unittest
from unittest.mock import patch
from acceptance.real_provider import local_environment


class AcceptanceLauncherTests(unittest.TestCase):
    def test_local_git_keeps_its_agent_but_provider_credentials_stay_out(self):
        with patch.dict(
            "os.environ",
            {
                "SSH_AUTH_SOCK": "fixture-agent",
                "HCLOUD_TOKEN": "fixture-secret",
                "HCLOUD_TOKEN_FILE": "fixture-private-path",
            },
            clear=True,
        ):
            env = local_environment()
        self.assertEqual(env["SSH_AUTH_SOCK"], "fixture-agent")
        self.assertNotIn("HCLOUD_TOKEN", env)
        self.assertNotIn("HCLOUD_TOKEN_FILE", env)

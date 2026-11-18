import unittest

from check_release_channels import check, verify_marketplace_source


class ChannelMappingTest(unittest.TestCase):
    def test_requires_exact_package_versions(self):
        for version in ("latest", "^0.5.1", ""):
            with self.assertRaisesRegex(ValueError, "exact version"):
                check({"pi": version, "claude_channel": "1.8.4"})
        check({"pi": "0.5.1", "claude_channel": "1.8.4"})

    def test_marketplace_must_pin_the_mapped_package(self):
        mapping = {"claude_channel": "1.8.4"}
        for source in (
            {"source": "npm", "package": "@awebai/claude-channel"},
            {"source": "npm", "package": "@awebai/claude-channel", "version": "latest"},
            {"source": "npm", "package": "@awebai/claude-channel", "version": "1.8.3"},
        ):
            document = {
                "name": "awebai-marketplace",
                "plugins": [{"name": "aweb-channel", "source": source}],
            }
            with self.assertRaisesRegex(
                ValueError, "Publish the exact mapped channel source"
            ):
                verify_marketplace_source(mapping=mapping, document=document)
        for source in (
            {"source": "npm", "package": "@awebai/claude-channel", "version": "1.8.4"},
            {"source": "npm", "package": "@awebai/claude-channel@1.8.4"},
        ):
            verify_marketplace_source(
                mapping=mapping,
                document={
                    "name": "awebai-marketplace",
                    "plugins": [{"name": "aweb-channel", "source": source}],
                },
            )


if __name__ == "__main__":
    unittest.main()

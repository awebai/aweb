"""The hook inventory resolves canonical constants and refuses dynamic names."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("extension_docs", ROOT / "scripts/check-extension-docs.py")
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class EventConstantInventoryTests(unittest.TestCase):
    def inventory(self, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "server/src/aweb"
            package.mkdir(parents=True)
            # Read the real single owner; the checker never imports/evaluates it.
            (package / "event_types.py").write_text(
                (ROOT / "server/src/aweb/event_types.py").read_text()
            )
            (package / "producer.py").write_text(source)
            failures = []
            sites = CHECKER._source_hook_call_sites(root, failures)
            return sites, failures

    def test_named_constants_and_import_aliases_resolve(self):
        for prefix, expression in (
            (
                "from aweb.event_types import MutationEventType",
                "MutationEventType.MAIL_SENT",
            ),
            (
                "from aweb.event_types import MutationEventType as Event",
                "Event.MAIL_SENT",
            ),
            (
                "from aweb.event_types import MutationEventType as Event",
                "Event.MAIL_SENT.value",
            ),
            ("import aweb.event_types as events", "events.MutationEventType.MAIL_SENT"),
            ("import aweb.event_types", "aweb.event_types.MutationEventType.MAIL_SENT"),
        ):
            with self.subTest(expression=expression):
                sites, failures = self.inventory(
                    prefix
                    + "\nasync def send():\n    await fire_mutation_callback(None, "
                    + expression
                    + ", {})\n"
                )
                self.assertEqual(failures, [])
                self.assertEqual([site["event"] for site in sites], ["message.sent"])

    def test_literals_and_repeated_call_sites_remain_counted(self):
        sites, failures = self.inventory(
            "async def send():\n"
            '    await fire_mutation_callback(None, "message.sent", {})\n'
            '    await fire_mutation_callback(None, "message.sent", {})\n'
        )
        self.assertEqual(failures, [])
        self.assertEqual(len(sites), 2)
        self.assertEqual(sites[0], sites[1])

    def test_both_conditional_branches_are_resolved(self):
        sites, failures = self.inventory(
            "from aweb.event_types import MutationEventType as Event\n"
            "async def send():\n"
            "    await fire_mutation_callback(None, Event.MAIL_SENT if incoming else "
            "Event.CHAT_MESSAGE_SENT, {})\n"
        )
        self.assertEqual(failures, [])
        self.assertEqual(
            [site["event"] for site in sites], ["chat.message_sent", "message.sent"]
        )

    def test_unknown_dynamic_or_wrong_owner_is_not_silently_omitted(self):
        for expression in (
            "dynamic_event_name",
            "Event.UNKNOWN_MEMBER",
            "TransportEventType.MAIL_DELIVERED",
            "Event.MAIL_SENT if incoming else dynamic_event_name",
            '"message.sent" if incoming else dynamic_event_name',
            'getattr(Event, "MAIL_SENT")',
        ):
            with self.subTest(expression=expression):
                sites, failures = self.inventory(
                    "from aweb.event_types import MutationEventType as Event, TransportEventType\n"
                    "async def send():\n    await fire_mutation_callback(None, "
                    + expression
                    + ", {})\n"
                )
                self.assertEqual(sites, [])
                self.assertTrue(
                    any("unsupported non-literal" in failure for failure in failures)
                )

    def test_shadowed_enum_reference_is_dynamic(self):
        for declaration in (
            "Event = external_value\nasync def send():",
            "async def send(Event):",
            "from other_module import Event\nasync def send():",
            "from aweb.event_types import MutationEventType as Event, TransportEventType as Event\nasync def send():",
            "Event.MAIL_SENT = external_value\nasync def send():",
        ):
            with self.subTest(declaration=declaration):
                sites, failures = self.inventory(
                    "from aweb.event_types import MutationEventType as Event\n"
                    + declaration
                    + "\n    await fire_mutation_callback(None, Event.MAIL_SENT, {})\n"
                )
                self.assertEqual(sites, [])
                self.assertTrue(
                    any("unsupported non-literal" in failure for failure in failures)
                )


if __name__ == "__main__":
    unittest.main()

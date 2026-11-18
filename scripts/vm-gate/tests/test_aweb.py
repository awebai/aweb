import unittest
from vm_gate.aweb import GateIntent, command
from vm_gate.errors import Refused

ALL = "checks user-paths unit artifacts integration"


class AwebAdapterTests(unittest.TestCase):
    def test_branch_default_keeps_shipped_default_entry(self):
        self.assertEqual(command(), "make candidate-gate")

    def test_train_reproduces_mac_command_without_profile_override(self):
        self.assertEqual(
            command(intent=GateIntent.TRAIN),
            "AWEB_CANDIDATE_STAGES='" + ALL + "' make candidate-gate",
        )

    def test_subset_uses_existing_selector_and_focused_command_is_unchanged(self):
        self.assertEqual(
            command(stages="all"),
            "AWEB_CANDIDATE_STAGES='" + ALL + "' make candidate-gate",
        )
        self.assertEqual(
            command(stages="artifacts integration"),
            "AWEB_CANDIDATE_STAGES='artifacts integration' make candidate-gate",
        )
        self.assertEqual(
            command(focused="make target ARG=value"), "make target ARG=value"
        )

    def test_unknown_duplicate_or_reordered_stages_refuse_before_allocation(self):
        for stages in ["unknown", "checks checks", "unit checks", ""]:
            with self.subTest(stages=stages), self.assertRaises(Refused):
                command(stages=stages)

    def test_unknown_intent_refuses_with_an_action(self):
        with self.assertRaisesRegex(Refused, "Choose branch or train"):
            command(intent="unknown")

    def test_train_cannot_be_a_partial_or_focused_gate(self):
        with self.assertRaises(Refused):
            command(intent=GateIntent.TRAIN, stages="unit")
        with self.assertRaises(Refused):
            command(intent=GateIntent.TRAIN, focused="true")


if __name__ == "__main__":
    unittest.main()

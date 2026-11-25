import unittest
from vm_gate.aweb import command
from vm_gate.errors import Refused

ALL = "static checks user-paths unit artifacts integration"


class AwebAdapterTests(unittest.TestCase):
    def test_train_reproduces_mac_command_without_profile_override(self):
        self.assertEqual(
            command(intent="train"),
            "AWEB_CANDIDATE_STAGES='" + ALL + "' make candidate-gate",
        )

    def test_unknown_duplicate_or_reordered_stages_refuse_before_allocation(self):
        for stages in ["unknown", "checks checks", "unit checks", ""]:
            with self.subTest(stages=stages), self.assertRaises(Refused):
                command(stages=stages)

    def test_train_cannot_be_a_partial_or_focused_gate(self):
        with self.assertRaises(Refused):
            command(intent="train", stages="unit")
        with self.assertRaises(Refused):
            command(intent="train", focused="true")


if __name__ == "__main__":
    unittest.main()

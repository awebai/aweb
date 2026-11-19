import unittest
from vm_gate.errors import Infrastructure, Refused
from vm_gate.expiry import CompletionBudget


class ExpiryTests(unittest.TestCase):
    def test_expiry_includes_all_work_and_survives_a_neighbor_reap(self):
        budget = CompletionBudget(
            100, 7200, setup=900, pull=600, cleanup=300, margin=300
        )
        self.assertEqual(budget.expires, 9445)
        budget.require("gate", now=1000)
        self.assertGreater(budget.expires, 1000 + 7200)

    def test_delayed_setup_refuses_gate_before_it_can_overrun_expiry(self):
        budget = CompletionBudget(
            100, 7200, setup=900, pull=600, cleanup=300, margin=300
        )
        with self.assertRaisesRegex(Infrastructure, "gate.*completion expiry"):
            budget.require("gate", now=1001)

    def test_pull_cannot_consume_teardown_or_margin(self):
        budget = CompletionBudget(100, 60, setup=10, pull=20, cleanup=30, margin=40)
        budget.require("pull", now=215)
        with self.assertRaises(Infrastructure):
            budget.require("pull", now=216)

    def test_timeout_zero_is_refused_locally(self):
        with self.assertRaises(Refused):
            CompletionBudget(100, 0)

    def test_allocation_time_reduces_setup_timeout_instead_of_refusing_every_run(self):
        budget = CompletionBudget(
            100, 7200, setup=900, pull=600, cleanup=300, margin=300
        )
        self.assertEqual(budget.require("setup", now=110), 890)
        with self.assertRaises(Infrastructure):
            budget.require("setup", now=1000)


if __name__ == "__main__":
    unittest.main()

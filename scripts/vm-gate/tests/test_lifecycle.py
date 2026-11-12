from pathlib import Path
import json
import tempfile
import unittest
from vm_gate.errors import Infrastructure, Refused
from vm_gate.lifecycle import run_session
from vm_gate.provider import Provider
from vm_gate.state import Store
from vm_gate.expiry import CompletionBudget


class Backend:
    def __init__(self):
        self.items = []
        self.calls = []
        self.counter = 0
        self.capacity = False

    def list(self, run_id=None):
        self.calls.append("inventory")
        return [dict(x) for x in self.items if run_id is None or x["run_id"] == run_id]

    def get(self, kind, id):
        return next(
            (x for x in self.items if x["kind"] == kind and x["id"] == id), None
        )

    def delete(self, item):
        self.calls.append("delete-" + item["kind"])
        self.items.remove(item)

    def create(self, kind, labels, **kwargs):
        self.calls.append("create-" + kind)
        if self.capacity and kind == "server":
            error = Exception()
            error.code = "resource_limit_exceeded"
            raise error
        self.counter += 1
        item = dict(kind=kind, id=self.counter, **labels)
        self.items.append(item)
        return item

    def create_key(self, **kwargs):
        return self.create("key", **kwargs)

    def create_ip(self, **kwargs):
        return self.create("ip", **kwargs)

    def create_server(self, **kwargs):
        return self.create("server", **kwargs)


class Remote:
    def __init__(self, exit=0, broken=False):
        self.exit = exit
        self.broken = broken
        self.prepared = False

    def prepare(self, server, timeout):
        self.prepared = True

    def execute(self, server, timeout):
        return self.exit

    def collect(self, server, timeout):
        if self.broken:
            raise Infrastructure("evidence transfer failed")
        return {
            "stages": [{"stage": "checks", "status": "PASSED", "seconds": 2}],
            "memory": {"host_peak": 10},
        }


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / "db", 150, clock=lambda: 100)
        self.backend = Backend()
        self.provider = Provider(self.backend, sleep=lambda _: None)
        self.budget = CompletionBudget(100, 60)

    def run_session(self, remote, **kw):
        return run_session(
            provider=self.provider,
            store=self.store,
            remote=remote,
            run_id="run",
            owner="seat",
            sha="a" * 40,
            budget=self.budget,
            directory=self.root / "run",
            server_type="ccx33",
            hourly_eur=".2",
            ip_hourly_eur=".01",
            clock=lambda: 100,
            **kw,
        )

    def test_known_bad_gate_exit_is_passed_through_with_cleanup(self):
        result = self.run_session(Remote(exit=7))
        self.assertEqual(result["exit"], 7)
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(self.backend.items, [])
        self.assertEqual(result["stages"][0]["seconds"], 2)
        self.assertEqual(
            json.loads((self.root / "run/summary.json").read_text())["exit"], 7
        )

    def test_lost_logs_cannot_prevent_deletion_or_become_success(self):
        result = self.run_session(Remote(broken=True))
        self.assertEqual(result["exit"], 70)
        self.assertEqual(result["infrastructure"], "infrastructure")
        self.assertEqual(self.backend.items, [])
        self.assertIsNotNone(self.store.get("run")["settled"])

    def test_reaper_runs_before_first_create_and_preserves_live_neighbor(self):
        self.store.reserve("expired", 1, now=1, expires=99)
        self.store.update(
            "expired",
            {
                "hourly_eur": ".2",
                "ip_hourly_eur": ".01",
                "resources": [{"kind": "server", "id": 99}],
            },
        )
        self.backend.items = [
            dict(kind="server", id=99, run_id="expired", expires=99),
            dict(kind="server", id=98, run_id="live", expires=99999),
        ]
        self.run_session(Remote())
        self.assertEqual(self.backend.calls[0], "inventory")
        self.assertLess(
            self.backend.calls.index("delete-server"),
            self.backend.calls.index("create-key"),
        )
        self.assertEqual([x["id"] for x in self.backend.items], [98])

    def test_controller_failure_retains_available_partial_stage_evidence(self):
        remote = Remote()

        def broken(server, timeout):
            raise Infrastructure("controller timeout")

        remote.execute = broken
        result = self.run_session(remote)
        self.assertEqual(result["exit"], 70)
        self.assertEqual(result["stages"][0]["stage"], "checks")
        self.assertEqual(self.backend.items, [])

    def test_capacity_is_one_refusal_and_no_second_type(self):
        self.backend.capacity = True
        result = self.run_session(Remote())
        self.assertEqual(result["exit"], 78)
        self.assertEqual(result["infrastructure"], "refused")
        self.assertIn("ccx33", result["error"])
        self.assertEqual(self.backend.calls.count("create-server"), 1)
        self.assertEqual(self.backend.items, [])

    def test_cap_refusal_allocates_nothing(self):
        self.store = Store(self.root / "small-db", 0.01, clock=lambda: 100)
        result = self.run_session(Remote())
        self.assertEqual(result["exit"], 78)
        self.assertFalse(any(x.startswith("create") for x in self.backend.calls))

    def test_per_run_acceptance_ceiling_refuses_live_price_before_create(self):
        result = self.run_session(Remote(), max_reserve_eur=".10")
        self.assertEqual(result["exit"], 78)
        self.assertIn("per-run ceiling", result["error"])
        self.assertFalse(any(x.startswith("create") for x in self.backend.calls))

    def test_cleanup_failure_cannot_settle_reservation_or_return_gate_pass(self):
        def fail(item):
            raise RuntimeError("lost provider")

        self.backend.delete = fail
        result = self.run_session(Remote())
        self.assertEqual(result["exit"], 70)
        self.assertIsNone(self.store.get("run")["settled"])

    def test_recorded_id_missing_from_label_list_cannot_be_claimed_absent(self):
        remote = Remote()

        def collect(server, timeout):
            self.backend.list = lambda run_id=None: []
            return {}

        remote.collect = collect
        result = self.run_session(remote)
        self.assertEqual(result["exit"], 70)
        self.assertIsNone(self.store.get("run")["settled"])

    def test_live_ip_rate_is_included_in_cost(self):
        result = self.run_session(Remote())
        self.assertEqual(result["cost_eur"], "0.21")

    def test_reconciled_uncertain_server_is_billed_and_deleted(self):
        real = self.backend.create_server

        def uncertain(**kwargs):
            real(**kwargs)
            error = Exception()
            error.code = "timeout"
            raise error

        self.backend.create_server = uncertain
        result = self.run_session(Remote())
        self.assertEqual(result["exit"], 70)
        self.assertEqual(result["cost_eur"], "0.21")
        self.assertEqual(self.backend.items, [])


if __name__ == "__main__":
    unittest.main()

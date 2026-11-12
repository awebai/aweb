from pathlib import Path
import tempfile
import unittest
from vm_gate.errors import Infrastructure
from vm_gate.provider import Provider
from vm_gate.reaping import reap_and_settle
from vm_gate.state import Store
from test_lifecycle import Backend


class ReapSettlementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / "db", 150, clock=lambda: 100)
        self.store.reserve("old", "2", now=100, expires=200)
        self.store.update(
            "old",
            {
                "hourly_eur": ".2",
                "ip_hourly_eur": ".01",
                "resources": [{"kind": "server", "id": 1}, {"kind": "ip", "id": 2}],
            },
        )
        self.backend = Backend()
        self.backend.items = [
            {"kind": "server", "id": 1, "run_id": "old", "expires": 200},
            {"kind": "ip", "id": 2, "run_id": "old", "expires": 200},
        ]
        self.provider = Provider(self.backend, sleep=lambda _: None)

    def test_reaped_expired_run_settles_conservatively_and_releases_reserve(self):
        reap_and_settle(self.provider, self.store, clock=lambda: 3701)
        row = self.store.get("old")
        self.assertEqual(row["actual"], "0.420000")
        self.assertEqual(self.store.totals(now=3701)["reserved"], "0.000000")
        self.assertEqual(self.backend.items, [])

    def test_missing_expiry_blocks_new_work_and_names_resource(self):
        self.backend.items[0].pop("expires")
        with self.assertRaisesRegex(Infrastructure, "server 1"):
            reap_and_settle(self.provider, self.store, clock=lambda: 3701)
        self.assertIsNone(self.store.get("old")["settled"])

    def test_missing_registry_price_holds_reservation(self):
        self.store.update("old", {"hourly_eur": None})
        with self.assertRaisesRegex(Infrastructure, "reservation held"):
            reap_and_settle(self.provider, self.store, clock=lambda: 3701)
        self.assertIsNone(self.store.get("old")["settled"])

    def test_reaped_snapshot_counts_both_vms_and_storage_upper_bound(self):
        self.store.update("old", {"server_attempts": 2, "storage_reserve_eur": ".1"})
        reap_and_settle(self.provider, self.store, clock=lambda: 3701)
        self.assertEqual(self.store.get("old")["actual"], "0.920000")


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import patch

from acceptance import merak_egress, merak_receipt

from vm_gate import merak_network


class MerakNetworkTests(unittest.TestCase):
    def test_guest_local_docker0_is_an_infrastructure_error(self):
        route = {"type": "local", "dev": "lo", "dst": "172.17.0.1"}
        for candidate in (
            route,
            {"dev": "docker0"},
            {"dev": "ens3", "gateway": "10.0.2.4"},
        ):
            with self.subTest(route=candidate), self.assertRaises(ValueError):
                merak_network.check_route(candidate, "ens3", "10.0.2.2")

    def test_host_docker0_via_gate_gateway_is_testable(self):
        route = {"dst": "172.17.0.1", "dev": "ens3", "gateway": "10.0.2.2"}
        merak_network.check_route(route, "ens3", "10.0.2.2")

    def test_rejects_overlapping_bridge_or_dynamic_network_pool(self):
        merak_network.check_subnets(["172.17.0.0/16", "172.18.0.0/16"])
        for network in ("10.240.0.0/24", "10.241.40.0/24"):
            with self.subTest(network=network), self.assertRaises(ValueError):
                merak_network.check_subnets([network])

    def test_guest_local_handshake_is_never_attempted_or_credited(self):
        with (
            patch.object(
                merak_egress,
                "guest_route",
                return_value={
                    "route": {"type": "local", "dev": "lo"},
                    "error": "guest local",
                },
            ),
            patch.object(merak_egress.socket, "create_connection") as connect,
        ):
            row = merak_egress.measure(
                {"kind": "refuse", "target": "172.17.0.1", "port": 22}
            )
        self.assertEqual(row["status"], "INFRA")
        connect.assert_not_called()

    def test_host_inventory_includes_loopback_and_distinguishes_listener_scope(self):
        addresses = [{"addr_info": [{"local": "127.0.0.1"}, {"local": "172.17.0.1"}]}]
        networks = [{"IPAM": {"Config": [{"Gateway": "172.18.0.1"}]}}]
        listeners = (
            "LISTEN 0 10 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 10 172.17.0.1:53 0.0.0.0:*"
        )
        rows = merak_receipt.host_controls(addresses, networks, listeners)
        self.assertEqual(len(rows), 6)
        self.assertEqual(
            [r["target"] for r in rows if r["port"] == 53 and r["listener_bound"]],
            ["172.17.0.1"],
        )

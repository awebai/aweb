import unittest
from types import SimpleNamespace
from hcloud import Client as RealClient
from importlib.metadata import version
from vm_gate.backend import Backend
from vm_gate.errors import Infrastructure


class APIError(Exception):
    def __init__(self, code):
        self.code = code


class Client:
    def __init__(self):
        self.calls = []
        self.deleted = []
        self._client = SimpleNamespace(_retry_max_retries=3)

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if method == "POST":
            return {}
        if method == "DELETE":
            self.deleted.append(url)
            return {}
        if url == "/servers":
            page = kw["params"]["page"]
            item = {
                "id": page,
                "labels": {
                    "aweb-vm-gate.run": "r",
                    "aweb-vm-gate.owner": "seat",
                    "aweb-vm-gate.sha": "a" * 40,
                    "aweb-vm-gate.expires": "999",
                },
            }
            return {
                "servers": [item],
                "meta": {"pagination": {"next_page": 2 if page == 1 else None}},
            }
        if url == "/servers/1":
            return {"server": {"id": 1, "labels": {"aweb-vm-gate.run": "other"}}}
        if method == "GET" and url.endswith("/404"):
            raise APIError("not_found")
        key = {
            "/primary_ips": "primary_ips",
            "/ssh_keys": "ssh_keys",
            "/images": "images",
        }[url]
        return {key: [], "meta": {"pagination": {"next_page": None}}}


class BackendTests(unittest.TestCase):
    def test_inventory_follows_pagination_and_keeps_expiry_as_number(self):
        c = Client()
        b = Backend(c, {})
        items = b.list("r")
        self.assertEqual([x["id"] for x in items], [1, 2])
        self.assertEqual(items[1]["expires"], 999)
        self.assertEqual(
            [x[2]["params"]["page"] for x in c.calls if x[1] == "/servers"], [1, 2]
        )

    def test_exact_id_not_found_only_is_absence(self):
        c = Client()
        b = Backend(c, {})
        self.assertIsNone(b.get("server", 404))

        def fail(*a, **kw):
            raise APIError("forbidden")

        c.request = fail
        with self.assertRaises(APIError):
            b.get("server", 404)

    def test_delete_refuses_label_changed_id(self):
        c = Client()
        b = Backend(c, {})
        with self.assertRaisesRegex(Infrastructure, "label mismatch"):
            b.delete({"kind": "server", "id": 1, "run_id": "r"})
        self.assertEqual(c.deleted, [])

    def test_real_pinned_sdk_has_mutation_retries_disabled_without_network(self):
        self.assertEqual(version("hcloud"), "2.27.0")
        client = RealClient(token="offline-fixture-token")
        Backend(client, {})
        self.assertEqual(client._client._retry_max_retries, 0)

    def test_unknown_sdk_retry_layout_refuses_before_any_network(self):
        c = Client()
        del c._client
        with self.assertRaisesRegex(Infrastructure, "retry setting"):
            Backend(c, {})
        self.assertEqual(c.calls, [])

    def test_retry_attribute_must_exist_before_assignment(self):
        c = Client()
        del c._client._retry_max_retries
        with self.assertRaisesRegex(Infrastructure, "retry setting"):
            Backend(c, {})
        self.assertEqual(c.calls, [])

    def test_b2_inventory_uses_a_namespace_distinct_from_live_b1_helpers(self):
        c = Client()
        Backend(c, {}).list("r")
        self.assertEqual(
            c.calls[0][2]["params"]["label_selector"], "aweb-vm-gate.run=r"
        )

    def test_expired_provider_deadline_cannot_start_a_mutation(self):
        import time

        c = Client()
        b = Backend(c, {})
        b.deadline = time.monotonic() - 1
        with self.assertRaisesRegex(Infrastructure, "deadline"):
            b.request("POST", "/servers", json={})
        self.assertEqual(c.calls, [])

    def test_primary_ip_payload_matches_the_real_pinned_sdk_without_network(self):
        from hcloud.locations import Location

        client = RealClient(token="offline-fixture-token")
        calls = []
        labels = {"run_id": "r", "owner": "seat", "sha": "a" * 40, "expires": 999}

        def capture(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return {
                "primary_ip": {"id": 1, "labels": kwargs["json"]["labels"]},
                "action": None,
            }

        client._client.request = capture
        client.primary_ips.create(
            name="r",
            type="ipv4",
            location=Location(name="location"),
            auto_delete=False,
            labels=Backend.labels(labels),
        )
        expected = calls[-1][2]["json"]
        Backend(client, {"location": "location", "datacenter": "legacy"}).create_ip(
            labels=labels
        )
        self.assertEqual(calls[-1][2]["json"], expected)

    def test_snapshot_is_protected_from_transient_cleanup_at_creation(self):
        client = RealClient(token="offline-fixture-token")
        calls = []

        def capture(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return {"image": {"id": 50}, "action": {"status": "success"}}

        client._client.request = capture
        backend = Backend(client, {})
        result = backend.create_image(
            server={"id": 3},
            labels={"run_id": "r", "owner": "seat", "sha": "a" * 40, "expires": 999},
        )
        labels = calls[-1][2]["json"]["labels"]
        self.assertNotIn("aweb-vm-gate.run", labels)
        self.assertEqual(labels["aweb-vm-gate.snapshot-run"], "r")
        self.assertEqual(labels["aweb-vm-gate.base"], "candidate")
        self.assertEqual(result["id"], 50)


if __name__ == "__main__":
    unittest.main()

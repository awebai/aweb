"""Hetzner SDK boundary. Mutations have no SDK retries; labels own every ID."""

import time
import json
from .errors import Infrastructure, Refused
from .provider import Provider

KINDS = {
    "server": ("servers", "server"),
    "ip": ("primary_ips", "primary_ip"),
    "key": ("ssh_keys", "ssh_key"),
    "image": ("images", "image"),
}
PREFIX = "aweb-vm-gate."


class Backend:
    def __init__(self, client, config):
        self.client = client
        self.config = config
        self.deadline = None
        # SDK's internal mutation retries must remain disabled.
        try:
            transport = client._client
            if not hasattr(transport, "_retry_max_retries"):
                raise AttributeError("unknown retry layout")
            transport._retry_max_retries = 0
            if transport._retry_max_retries != 0:
                raise ValueError("retry setting did not change")
        except Exception:
            raise Infrastructure(
                "SDK mutation retry setting unavailable or nonzero; refusing provider access"
            ) from None

    def request(self, method, url, **kwargs):
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise Infrastructure("provider completion deadline exhausted")
            kwargs["timeout"] = (min(10, remaining / 2), min(60, remaining / 2))
        return self.client.request(method, url, **kwargs)

    @staticmethod
    def labels(values):
        names = {"run_id": "run", "owner": "owner", "sha": "sha", "expires": "expires"}
        return {PREFIX + names[k]: str(values[k]) for k in names}

    @staticmethod
    def resource(kind, item):
        labels = item.get("labels", {})
        expiry = labels.get(PREFIX + "expires")
        try:
            expiry = int(expiry)
        except (TypeError, ValueError):
            expiry = None
        return {
            "kind": kind,
            "id": item["id"],
            "run_id": labels.get(PREFIX + "run"),
            "expires": expiry,
            "owner": labels.get(PREFIX + "owner"),
            "sha": labels.get(PREFIX + "sha"),
            "created": item.get("created"),
        }

    def list(self, run_id=None):
        selector = PREFIX + "run" + ("=" + run_id if run_id else "")
        items = []
        for kind, (plural, _) in KINDS.items():
            page = 1
            seen = set()
            while page:
                if page in seen or len(seen) >= 1000:
                    raise Infrastructure("provider pagination did not terminate")
                seen.add(page)
                params = {"label_selector": selector, "page": page, "per_page": 50}
                if kind == "image":
                    params["type"] = "snapshot"
                result = self.request("GET", "/" + plural, params=params)
                items.extend(self.resource(kind, item) for item in result[plural])
                page = result.get("meta", {}).get("pagination", {}).get("next_page")
        return items

    def _get(self, kind, id):
        plural, singular = KINDS[kind]
        try:
            return self.request("GET", f"/{plural}/{id}")[singular]
        except Exception as exc:
            if getattr(exc, "code", None) == "not_found":
                return None
            raise

    def get(self, kind, id):
        item = self._get(kind, id)
        return self.resource(kind, item) if item else None

    def action(self, id):
        return self.request("GET", f"/actions/{id}")["action"]

    def wait(self, action, seconds=120):
        deadline = time.monotonic() + seconds
        reads = Provider(self)
        while action and action["status"] == "running":
            if time.monotonic() >= deadline:
                raise Infrastructure("provider action did not finish before deadline")
            time.sleep(1)
            action = reads.read("action", action["id"])
        if action and action["status"] == "error":
            raise Infrastructure(
                "provider action failed: "
                + action.get("error", {}).get("code", "unknown")
            )

    def delete(self, item):
        current = self._get(item["kind"], item["id"])
        if current is None:
            return
        if current.get("labels", {}).get(PREFIX + "run") != item["run_id"]:
            raise Infrastructure(
                f"delete label mismatch for {item['kind']} {item['id']}"
            )
        plural, _ = KINDS[item["kind"]]
        result = self.request("DELETE", f"/{plural}/{item['id']}")
        if result:
            self.wait(result.get("action"))

    def create_key(self, *, labels):
        result = self.request(
            "POST",
            "/ssh_keys",
            json={
                "name": labels["run_id"],
                "public_key": self.config["public_key"],
                "labels": self.labels(labels),
            },
        )
        return self.resource("key", result["ssh_key"])

    def create_ip(self, *, labels):
        result = self.request(
            "POST",
            "/primary_ips",
            json={
                "name": labels["run_id"],
                "type": "ipv4",
                "location": self.config["location"],
                "auto_delete": False,
                "labels": self.labels(labels),
            },
        )
        self.wait(result.get("action"))
        return self.resource("ip", result["primary_ip"])

    def create_server(self, *, server_type, labels, key, ip):
        private = self.config.get("ssh_host_private")
        public = self.config.get("ssh_host_public")
        if not private or not public:
            raise Infrastructure("per-run SSH host key missing; refusing server create")
        user_data = "#cloud-config\n" + json.dumps(
            {
                "ssh_deletekeys": True,
                "ssh_genkeytypes": [],
                "ssh_keys": {"ed25519_private": private, "ed25519_public": public},
            }
        )
        result = self.request(
            "POST",
            "/servers",
            json={
                "name": labels["run_id"],
                "server_type": server_type,
                "image": self.config["snapshot_id"],
                "ssh_keys": [key["id"]],
                "user_data": user_data,
                "location": self.config["location"],
                "public_net": {
                    "enable_ipv4": True,
                    "enable_ipv6": False,
                    "ipv4": ip["id"],
                },
                "labels": self.labels(labels),
            },
        )
        # Return before waiting: the registry records the ID before SSH starts.
        return self.resource("server", result["server"])

    def server_info(self, id):
        return self.request("GET", f"/servers/{id}")["server"]

    def image_info(self, id):
        return self.request("GET", f"/images/{id}")["image"]

    def pricing(self, server_type):
        result = self.request("GET", "/pricing")["pricing"]
        if result["currency"] != "EUR":
            raise Refused("provider pricing currency must be EUR")
        types = self.request("GET", "/server_types", params={"name": server_type})[
            "server_types"
        ]
        if len(types) != 1:
            raise Refused(f"requested server type unavailable: {server_type}")
        price = next(
            (p for p in types[0]["prices"] if p["location"] == self.config["location"]),
            None,
        )
        if price is None:
            raise Refused("no price at configured location")
        ip = next((p for p in result["primary_ips"] if p["type"] == "ipv4"), None)
        if ip is None:
            raise Refused("no IPv4 pricing")
        ip_price = next(
            (p for p in ip["prices"] if p["location"] == self.config["location"]), None
        )
        if ip_price is None:
            raise Refused("no IPv4 price at configured location")
        return {
            "server_hourly": price["price_hourly"]["gross"],
            "ip_hourly": ip_price["price_hourly"]["gross"],
            "currency": "EUR",
            "disk": types[0]["disk"],
        }

    def snapshot_pricing(self):
        return self.request("GET", "/pricing")["pricing"]

    def create_image(self, *, server, labels):
        protected = self.labels(labels)
        protected[PREFIX + "snapshot-run"] = protected.pop(PREFIX + "run")
        protected[PREFIX + "base"] = "candidate"
        result = self.request(
            "POST",
            f"/servers/{server['id']}/actions/create_image",
            json={
                "type": "snapshot",
                "description": labels["run_id"],
                "labels": protected,
            },
        )
        return {"id": result["image"]["id"], "action": result.get("action")}

    def snapshot_candidates(self, run_id):
        page = 1
        items = []
        seen = set()
        while page:
            if page in seen or len(seen) >= 1000:
                raise Infrastructure("snapshot pagination did not terminate")
            seen.add(page)
            result = self.request(
                "GET",
                "/images",
                params={
                    "type": "snapshot",
                    "label_selector": PREFIX + "snapshot-run=" + run_id,
                    "page": page,
                    "per_page": 50,
                },
            )
            items.extend(
                {"kind": "image", "id": item["id"], "snapshot_run": run_id}
                for item in result["images"]
            )
            page = result.get("meta", {}).get("pagination", {}).get("next_page")
        return items

    def promote_image(self, id, run_id):
        image = self.image_info(id)
        labels = dict(image.get("labels", {}))
        if labels.get(PREFIX + "snapshot-run") != run_id:
            raise Infrastructure("snapshot promotion label mismatch")
        labels[PREFIX + "base"] = "verified"
        self.request("PUT", f"/images/{id}", json={"labels": labels})

    def delete_base(self, id, new_id):
        if id == new_id:
            raise Infrastructure("old and new base IDs must differ")
        image = self.image_info(id)
        if image["type"] != "snapshot":
            raise Infrastructure("configured old base is not a snapshot")
        self.request("DELETE", f"/images/{id}")

"""Expiry recovery settles only after label and recorded exact-ID absence."""

from decimal import Decimal
import math
import time
from .errors import Infrastructure


def reap_and_settle(provider, store, clock=time.time):
    reaped = provider.reap(clock())
    now = clock()
    settled = []
    for receipt in reaped:
        if store.get(receipt["run_id"]) is None:
            raise Infrastructure(
                f"reaped run {receipt['run_id']} has no spend registry; cost unknown"
            )
    for row in store.expired(now):
        run_id = row["run_id"]
        resources = row.get("resources", [])
        if provider.read("list", run_id) or any(
            provider.read("get", x["kind"], x["id"]) is not None for x in resources
        ):
            raise Infrastructure(
                f"reaped run {run_id} still has resources; reservation held"
            )
        if row.get("hourly_eur") is None or row.get("ip_hourly_eur") is None:
            raise Infrastructure(f"reaped run {run_id} lacks pricing; reservation held")
        hours = max(1, math.ceil((now - row["created"]) / 3600))
        server = max(
            len({x["id"] for x in resources if x["kind"] == "server"}),
            row.get("server_attempts", int(row.get("attempted_server", False))),
        )
        ip = any(x["kind"] == "ip" for x in resources) or row.get("attempted_ip", False)
        actual = hours * (
            Decimal(row["hourly_eur"]) * int(server)
            + Decimal(row["ip_hourly_eur"]) * int(ip)
        ) + Decimal(row.get("storage_reserve_eur", "0"))
        store.settle(run_id, str(actual), now=now)
        store.update(
            run_id,
            {"reaped": now, "cost_basis": "conservative creation-to-reap upper bound"},
        )
        settled.append({"run_id": run_id, "cost_eur": str(actual)})
    return {"resources": reaped, "settled": settled}

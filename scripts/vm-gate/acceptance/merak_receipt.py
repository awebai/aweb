"""Evidence for the fixed Merak deployment controls and host-local destinations."""

import ipaddress
import json
from pathlib import Path


def host_controls(addresses, networks, listeners):
    """Use actual host inventory, retaining whether a second listener is bound there."""
    bindings = []
    for line in listeners.splitlines():
        endpoint = line.split()[3]
        address, port = endpoint.rsplit(":", 1)
        bindings.append((address.strip("[]").split("%")[0], int(port)))
    other_ports = sorted({port for _, port in bindings if port != 22})
    rows = []
    targets = {entry["local"] for dev in addresses for entry in dev["addr_info"]}
    targets.update(
        row["Gateway"]
        for network in networks
        for row in network["IPAM"]["Config"]
        if row.get("Gateway")
    )
    for target in sorted(targets):
        ip = ipaddress.ip_address(target)
        wildcard = "::" if ip.version == 6 else "0.0.0.0"
        bound = sorted(
            {port for addr, port in bindings if addr in (target, wildcard, "*")}
        )
        secondary = next((port for port in bound if port != 22), None)
        ports = [22]
        if secondary or other_ports:
            ports.append(secondary or other_ports[0])
        for port in ports:
            rows.append(
                {
                    "kind": "refuse",
                    "target": target,
                    "port": port,
                    "host_local": True,
                    "listener_bound": port in bound,
                    "secondary_available": secondary is not None,
                }
            )
    return rows


def host_drop_counters(snapshot):
    """Read the reviewed non-unicast and host input drops by expression, not rule number."""
    totals = {}
    for entry in snapshot["rules"]["nftables"]:
        rule = entry.get("rule")
        if not rule or {"drop": None} not in rule["expr"]:
            continue
        matches = [term["match"] for term in rule["expr"] if "match" in term]
        local = any(
            match.get("left", {}).get("fib") == {"result": "type", "flags": ["daddr"]}
            and match["op"] == "!="
            and match["right"] == "unicast"
            for match in matches
        )
        host_input = rule["chain"] == "host_input" and any(
            m.get("left") == {"meta": {"key": "iifname"}}
            and m.get("right") == snapshot["bridge"]
            for m in matches
        )
        if local or host_input:
            (counter,) = [term["counter"] for term in rule["expr"] if "counter" in term]
            totals[rule["chain"]] = counter["packets"]
    if totals.keys() != {"destinations", "host_input"}:
        raise ValueError("missing run-bridge local-destination or input drop counter")
    return totals


def record_control(index, row, before, after, directory):
    if not (
        before["run"] == after["run"]
        and before["bridge"] == after["bridge"]
        and before["helper_sha256"] == after["helper_sha256"]
        and before["present"]
        and after["present"]
    ):
        raise ValueError("counter snapshots differ in run, bridge or helper")
    for label, snapshot in (("before", before), ("after", after)):
        path = Path(directory) / f"control-{index:03}-{label}.json"
        path.write_text(json.dumps(snapshot, indent=2) + "\n")
    first, last = host_drop_counters(before), host_drop_counters(after)
    row["host_drop_delta"] = {name: last[name] - count for name, count in first.items()}
    if row["status"] == "REFUSAL_OBSERVED":
        if row.get("host_local") and not any(
            count > 0 for count in row["host_drop_delta"].values()
        ):
            row.update(
                status="INFRA",
                reason="no matching host drop counter advanced in this interval",
            )
        else:
            row["status"] = "PASS"
    return row


def collect(executor, host, run, original_controls, probe_script):
    """Controller-side collection on one admitted guest. Host inventories stay on the controller."""
    directory = executor.directory / "boundary"
    directory.mkdir(mode=0o700)

    def save(name, value):
        path = directory / name
        path.write_text(json.dumps(value, indent=2) + "\n")
        return path

    def snapshot():
        return json.loads(
            host("sudo", "-n", "/usr/local/sbin/aweb-merak-egress", "show", run)
        )

    admission = json.loads((executor.directory / "summary.json").read_text())[
        "admission"
    ]
    loaded = snapshot()
    if not (
        loaded["present"]
        and loaded["run"] == run
        and loaded["helper_sha256"] == admission["egress"]["helper_sha256"]
    ):
        raise ValueError("live Merak policy does not match admission")
    addresses = json.loads(host("ip", "-j", "addr"))
    networks = json.loads(
        host(
            "docker",
            "network",
            "inspect",
            *host("docker", "network", "ls", "-q", "--filter", "driver=bridge").split(),
        )
    )
    listeners = host("ss", "-H", "-ltn")
    save(
        "host-inventory.json",
        {
            "addresses": addresses,
            "bridges": networks,
            "tcp_listeners": listeners,
            "launcher_networks": json.loads(
                host(
                    "docker",
                    "inspect",
                    "--format",
                    "{{json .NetworkSettings.Networks}}",
                    admission["container"],
                )
            ),
        },
    )
    save("rules-before.json", loaded)
    inventory = host_controls(addresses, networks, listeners)
    controls = [dict(item, original=True) for item in original_controls]
    if len(controls) != 15:
        raise ValueError("expected the fifteen original Merak controls")
    for extra in inventory:
        duplicate = next(
            (
                item
                for item in controls
                if (item["kind"], item["target"], item.get("port"))
                == (extra["kind"], extra["target"], extra["port"])
            ),
            None,
        )
        if duplicate is None:
            controls.append(extra)
        else:
            duplicate.update(extra)
    plan = save("controls.json", {"run": run, "controls": controls})
    executor.upload(plan, "/opt/vm-gate/boundary-controls.json", mode="0444")
    executor.upload(probe_script, "/opt/vm-gate/boundary-probe.py", mode="0444")
    rows = []
    for index, control in enumerate(controls):
        before = snapshot()
        measurement = executor.run(
            "runuser -u gateuser -- python3 -I /opt/vm-gate/boundary-probe.py "
            f"/opt/vm-gate/boundary-controls.json {index}",
            f"boundary-{index:03}",
        )
        row = json.loads(measurement.stdout)
        if not all(row.get(k) == v for k, v in control.items()):
            raise ValueError("guest measurement differs from the selected control")
        rows.append(record_control(index, row, before, snapshot(), directory))
        save("measurements.json", rows)
    save("rules-after.json", snapshot())
    receipt = save(
        "receipt.json",
        {
            "run": run,
            "controls": rows,
            "helper_sha256": loaded["helper_sha256"],
            "firewall_scope": "run-owned table only; other host tables not captured",
        },
    )
    executor.upload(receipt, "/opt/vm-gate/boundary-receipt.json", mode="0444")

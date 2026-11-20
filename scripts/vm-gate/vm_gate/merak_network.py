"""Network setup and route attribution inside a disposable Merak guest."""

import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys

DOCKER_NETWORK = {
    "bip": "10.240.0.1/24",
    "default-address-pools": [{"base": "10.241.0.0/16", "size": 24}],
}


def check_subnets(host_subnets):
    guest = [ipaddress.ip_interface(DOCKER_NETWORK["bip"]).network]
    guest.extend(
        ipaddress.ip_network(p["base"]) for p in DOCKER_NETWORK["default-address-pools"]
    )
    for value in host_subnets:
        subnet = ipaddress.ip_network(value, strict=False)
        if any(
            subnet.overlaps(pool) for pool in guest if pool.version == subnet.version
        ):
            raise ValueError(
                f"Merak host network {subnet} overlaps guest Docker allocation"
            )


def check_route(route, nic, gateway):
    if (
        route.get("type", "unicast") != "unicast"
        or route.get("dev") != nic
        or not gateway
        or route.get("gateway") != gateway
    ):
        raise ValueError(
            f"route does not leave via gate NIC {nic} and gateway {gateway}: {route}"
        )


def output(*args):
    return subprocess.check_output(args, text=True, timeout=45)


def inspect_route(address):
    family = "-4" if ipaddress.ip_address(address).version == 4 else "-6"
    nics = json.loads(output("ip", "-j", "link"))
    (nic,) = [
        item["ifname"] for item in nics if item.get("address") == "52:54:00:aa:bb:01"
    ]
    (route,) = json.loads(output("ip", "-j", family, "route", "get", address))
    if route.get("type") == "local":
        return {"route": route, "error": "lookup resolved inside the guest"}
    (default,) = json.loads(
        output("ip", "-j", family, "route", "show", "default", "dev", nic)
    )
    if family == "-4" and default.get("gateway") != "10.0.2.2":
        return {
            "route": route,
            "error": "gate NIC default differs from the QEMU user-network gateway",
        }
    try:
        check_route(route, nic, default.get("gateway"))
    except ValueError as exc:
        return {"route": route, "error": str(exc)}
    return {"route": route}


def configure():
    path = Path("/etc/docker/daemon.json")
    path.parent.mkdir(exist_ok=True)
    config = json.loads(path.read_text()) if path.exists() else {}
    config.update(DOCKER_NETWORK)
    with tempfile.NamedTemporaryFile(dir=path.parent, mode="w", delete=False) as stream:
        temp = Path(stream.name)
        json.dump(config, stream)
    try:
        output("dockerd", "--validate", "--config-file", str(temp))
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    output("systemctl", "restart", "docker")
    (bridge,) = json.loads(output("docker", "network", "inspect", "bridge"))
    actual = bridge["IPAM"]["Config"]
    bip = ipaddress.ip_interface(DOCKER_NETWORK["bip"])
    if not any(
        row.get("Gateway") == str(bip.ip) and row.get("Subnet") == str(bip.network)
        for row in actual
    ):
        raise ValueError(
            f"Docker bridge differs from the guest network manifest: {actual}"
        )
    # Verify dynamic allocation through the daemon itself. Removal is confined
    # to the temporary network ID just returned by this guest's daemon.
    network = output("docker", "network", "create", "merak-address-pool-check").strip()
    try:
        (allocated,) = json.loads(output("docker", "network", "inspect", network))
        (ipv4,) = [
            ipaddress.ip_network(row["Subnet"])
            for row in allocated["IPAM"]["Config"]
            if ipaddress.ip_network(row["Subnet"]).version == 4
        ]
        if not any(
            ipv4.subnet_of(ipaddress.ip_network(p["base"]))
            and ipv4.prefixlen == p["size"]
            for p in DOCKER_NETWORK["default-address-pools"]
        ):
            raise ValueError(f"unexpected guest Docker subnet {ipv4}")
    finally:
        output("docker", "network", "rm", network)
    addresses = json.loads(output("ip", "-j", "addr"))
    actual_ips = {
        entry["local"]
        for link in addresses
        if link["ifname"] == "docker0"
        for entry in link["addr_info"]
        if entry["family"] == "inet"
    }
    if actual_ips != {str(bip.ip)}:
        raise ValueError(f"unexpected guest docker0 addresses {sorted(actual_ips)}")
    return {
        "daemon_network": DOCKER_NETWORK,
        "bridge": actual,
        "sample_allocation": str(ipv4),
        "addresses": addresses,
        "routes": {
            family: json.loads(
                output("ip", "-j", family, "route", "show", "table", "all")
            )
            for family in ("-4", "-6")
        },
    }


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "route":
        try:
            print(json.dumps(inspect_route(sys.argv[2])))
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            sys.exit(str(exc))
    elif len(sys.argv) == 1:
        print(json.dumps(configure()))
    else:
        sys.exit("expected no arguments or route ADDRESS")

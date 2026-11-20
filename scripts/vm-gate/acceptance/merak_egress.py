"""Measure one approved control from the guest, between two host counter reads."""

from contextlib import closing
import datetime
import errno
import http.client
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys

PUBLIC_HTTPS = {"example.com": "/", "pypi.org": "/simple/pip/"}
RESOLVERS = {"1.1.1.1", "9.9.9.9"}


def guest_route(address):
    # Installed by the execution controller, independently of the tested checkout.
    result = subprocess.run(
        ["/usr/bin/python3", "-I", "/run/merak_network.py", "route", address],
        timeout=10,
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError(result.stderr.strip() or "missing guest route")
    return json.loads(result.stdout)


def https_head(host, address):
    with socket.create_connection((address, 443), timeout=10) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
            with closing(http.client.HTTPSConnection(host, timeout=10)) as client:
                client.sock = tls
                client.request("HEAD", PUBLIC_HTTPS[host])
                response = client.getresponse()
                if response.status != 200:
                    raise OSError(f"HTTP status {response.status}")
                return {"http_status": response.status}


def dns(address):
    from os import urandom

    nonce = urandom(2)
    query = (
        nonce
        + struct.pack("!5H", 256, 1, 0, 0, 0)
        + b"\x07example\x03com\x00\x00\x01\x00\x01"
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.connect((address, 53))
        sock.send(query)
        reply = sock.recv(4096)
    ident, flags, questions, answers, _, _ = struct.unpack("!2s5H", reply[:12])
    if (
        ident != nonce
        or not flags & 0x8000
        or flags & 15
        or questions != 1
        or answers < 1
    ):
        raise OSError("resolver did not answer the question")
    return {"dns_answers": answers}


def measure(control):
    kind, target = control["kind"], control["target"]
    row = dict(
        control,
        status="INFRA",
        utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
    try:
        if kind == "https" and target in PUBLIC_HTTPS:
            # Use the same concrete address for route lookup and TLS.
            address = socket.getaddrinfo(
                target, 443, socket.AF_INET, socket.SOCK_STREAM
            )[0][4][0]
        elif kind == "refuse" or (kind == "dns" and target in RESOLVERS):
            address = str(ipaddress.ip_address(target))
        else:
            raise ValueError("unknown boundary control")
        row["address"] = address
        lookup = guest_route(address)
        row["route"] = lookup["route"]
        if "error" in lookup:
            row["reason"] = lookup["error"]
            return row
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        row["reason"] = str(exc)
        return row
    try:
        if kind == "https":
            row.update(https_head(target, address))
        elif kind == "dns":
            row.update(dns(address))
        else:
            with socket.create_connection((address, control["port"]), timeout=3):
                row["application_bytes_sent"] = 0
        row["status"] = "FAIL" if kind == "refuse" else "PASS"
    except (OSError, http.client.HTTPException, struct.error) as exc:
        row["reason"] = str(exc)
        if kind == "refuse":
            # Host counters corroborate attribution; local bind/route failures
            # cannot establish a firewall denial.
            if (
                isinstance(exc, TimeoutError)
                or getattr(exc, "errno", None) == errno.ECONNREFUSED
            ):
                row["status"] = "REFUSAL_OBSERVED"
        else:
            row["status"] = "FAIL"
    return row


if __name__ == "__main__":
    if sys.argv[1:] == ["--receipt"]:
        receipt = json.loads(Path("/opt/vm-gate/boundary-receipt.json").read_text())
        rows = receipt["controls"]
        print(json.dumps(receipt, indent=2))
        if any(row["status"] == "FAIL" for row in rows):
            sys.exit(1)
        # Local loopbacks have no off-guest target. Retain their INFRA rows;
        # every original control and every other inventoried row must pass.
        incomplete = any(
            row["status"] != "PASS"
            and (
                row.get("original")
                or row["status"] != "INFRA"
                or row.get("route", {}).get("type") != "local"
                or not ipaddress.ip_address(row["target"]).is_loopback
            )
            for row in rows
        )
        sys.exit(70 if incomplete else 0)
    manifest = json.loads(Path(sys.argv[1]).read_text())
    print(json.dumps(measure(manifest["controls"][int(sys.argv[2])])))

#!/usr/bin/python3 -I
"""Root-owned Merak bridge policy. Install once using sudo ./merak_egress.py install."""

import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile

HELPER = Path("/usr/local/sbin/aweb-merak-egress")
SUDOERS = Path("/etc/sudoers.d/aweb-merak-egress")
NFT = "/usr/bin/nft"
IP = "/usr/bin/ip"
# IPv4 destinations which cannot be ordinary remote internet endpoints.
NON_PUBLIC = (
    "0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, "
    "172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, "
    "192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, "
    "224.0.0.0/4, 240.0.0.0/4"
)
RESOLVERS = ("1.1.1.1", "9.9.9.9")


def invoke(*args, data=None):
    return subprocess.run(
        args,
        input=data,
        text=True,
        capture_output=True,
        check=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        timeout=15,
    ).stdout


def install():
    user = os.environ.get("SUDO_USER", "")
    if not re.fullmatch("[a-z_][a-z0-9_-]*", user) or pwd.getpwnam(user).pw_uid == 0:
        raise ValueError("install using sudo from the Merak operator login")
    for tool in [NFT, IP, "/usr/bin/visudo", "/usr/bin/unshare"]:
        if not os.access(tool, os.X_OK):
            raise ValueError("missing executable: " + tool)
    # Exercise the installed kernel and nft syntax in a temporary network
    # namespace before granting access. Its rules disappear with the process.
    invoke(
        "/usr/bin/unshare",
        "--net",
        "--",
        NFT,
        "-f",
        "-",
        data=policy("aweb_install_check", "aginstallcheck", "eth0"),
    )
    # Validate the grant before replacing either root-owned file. Root selects the
    # reviewed source at install time; runtime callers can supply only a run ID.
    rules = ", ".join(
        str(HELPER) + " " + action + " vm-*" for action in ["add", "remove", "show"]
    )
    grant = f"{user} ALL=(root) NOPASSWD: {rules}\n"
    with tempfile.NamedTemporaryFile(dir=SUDOERS.parent, prefix=".aweb-") as test:
        test.write(grant.encode())
        test.flush()
        invoke("/usr/bin/visudo", "-cf", test.name)
    for path, data, mode in [
        (HELPER, Path(__file__).read_bytes(), 0o755),
        (SUDOERS, grant.encode(), 0o440),
    ]:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".aweb-", delete=False
        ) as fp:
            temp = Path(fp.name)
            try:
                fp.write(data)
                fp.flush()
                os.fchmod(fp.fileno(), mode)
                os.replace(temp, path)
            finally:
                temp.unlink(missing_ok=True)
    print("Installed Merak egress helper and restricted sudo grant")


def policy(table, bridge, uplink):
    # prerouting precedes Docker DNAT. Forward checks the translated destination
    # and actual output interface before Docker's filter priority (0).
    return f"""table inet {table} {{
 chain destinations {{
  meta nfproto != ipv4 counter drop
  fib daddr type != unicast counter drop
  ip daddr {{ {NON_PUBLIC} }} counter drop
  ip daddr != {{ {", ".join(RESOLVERS)} }} meta l4proto {{ tcp, udp }} th dport 53 counter drop
 }}
 chain before_dnat {{
  type filter hook prerouting priority -110; policy accept;
  iifname "{bridge}" jump destinations
 }}
 chain host_input {{
  type filter hook input priority -10; policy accept;
  iifname "{bridge}" counter drop
 }}
 chain outbound {{
  type filter hook forward priority -10; policy accept;
  iifname "{bridge}" oifname != "{uplink}" counter drop
  iifname "{bridge}" jump destinations
 }}
}}
"""


def manage(action, run):
    if not re.fullmatch(r"vm-[0-9a-f]{32}", run) or action not in {
        "add",
        "show",
        "remove",
    }:
        raise ValueError("expected add|show|remove and a Merak run ID")
    table = "aweb_" + run[3:]
    bridge = "ag" + run[3:16]

    def exists():
        tables = json.loads(invoke(NFT, "-j", "list", "tables"))["nftables"]
        return any(
            t.get("table", {}).get("name") == table and t["table"]["family"] == "inet"
            for t in tables
        )

    if action == "add":
        if exists() or Path("/sys/class/net", bridge).exists():
            raise ValueError("run table or bridge already present")
        # Fail closed when the public route no longer uses a physical interface.
        (route,) = json.loads(invoke(IP, "-j", "-4", "route", "get", RESOLVERS[0]))
        uplink = route["dev"]
        if (
            not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", uplink)
            or not Path("/sys/class/net", uplink, "device").exists()
        ):
            raise ValueError("public route has no physical uplink")
        invoke(NFT, "-f", "-", data=policy(table, bridge, uplink))
    if action == "remove":
        if Path("/sys/class/net", bridge).exists():
            raise ValueError("refusing to remove egress policy while bridge exists")
        if exists():
            invoke(NFT, "delete", "table", "inet", table)
        if exists():
            raise RuntimeError("egress table remains")
    present = exists()
    if action == "add" and not present:
        raise RuntimeError("egress policy missing")
    print(
        json.dumps(
            {
                "run": run,
                "bridge": bridge,
                "table": table,
                "present": present,
                "dns": RESOLVERS,
                "helper_sha256": hashlib.sha256(
                    Path(__file__).read_bytes()
                ).hexdigest(),
                "rules": json.loads(invoke(NFT, "-j", "list", "table", "inet", table))
                if present
                else None,
            }
        )
    )


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("root required for Merak host firewall")
    if sys.argv[1:] == ["install"]:
        install()
    elif len(sys.argv) == 3:
        manage(*sys.argv[1:])
    else:
        sys.exit("use install or add|show|remove vm-<32 hex>")

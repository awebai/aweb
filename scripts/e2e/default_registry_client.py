#!/usr/bin/env python3
"""Published aw's default-registry onboarding and mail, inside a lab client.

The outer lab owns DNS/TLS/stock services. No registry URL override, source CLI,
handwritten identity, development setting or service token is accepted here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
from registry_quota_probe import exercise


VERSION = "1.36.59-rc.2"
BINARY_SHA256 = "a4ff118eb7f0746804f2d579995607aefcdaf888b68eb17c6d4fe7260ba52545"
SOURCE_SHA = "0072ed1c1c7545c59ce743c9cea431e4ce96afcb"
REGISTRY = "https://api.awid.ai"
SERVICE = "https://server.adaz.test:8443"
DOMAINS = {"alice": "alice.adaz.example.com", "bob": "bob.adaz.example.net"}


def write_zone(path, public_ip, records):
    previous = re.search(r"\((\d+) ", path.read_text()) if path.exists() else None
    serial = (int(previous[1]) + 1) % (2**32) if previous else 1
    text = ("$ORIGIN .\n$TTL 0\n"
            f". IN SOA ns.adaz.test. hostmaster.adaz.test. ({serial} 1 1 1 1)\n"
            ". IN NS ns.adaz.test.\nns.adaz.test. IN A 127.0.0.1\n"
            f"api.awid.ai. IN A {public_ip}\nserver.adaz.test. IN A {public_ip}\n"
            "private-registry.adaz.test. IN A 127.0.0.1\n")
    for domain, value in sorted(records.items()):
        if not value or any(ord(c) < 32 or ord(c) > 126 for c in value) or len(value) > 255:
            raise ValueError("unsafe DNS TXT value")
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        text += f'_awid.{domain}. IN TXT "{escaped}"\n'
    temporary = path.with_suffix(".new")
    temporary.write_text(text)
    temporary.chmod(0o644)
    temporary.replace(path)


class Journey:
    def __init__(self, work, public_ip):
        self.work, self.public_ip = work, public_ip
        self.binary = Path("/published/aw")
        if hashlib.file_digest(self.binary.open("rb"), "sha256").hexdigest() != BINARY_SHA256:
            raise ValueError("published Linux CLI differs from frozen npm artifact")
        self.homes = {}
        self.records = {}
        self.bindings = {}
        self.outcomes = {}
        for name in ("alice", "bob", "reader", "negative"):
            root = work / name
            root.mkdir(mode=0o700)
            (root / "workspace").mkdir(mode=0o700)
            self.homes[name] = root

    def command(self, actor, *args, success=True):
        forbidden = {"--registry", "--awid-registry", "--skip-dns-verify", "--insecure"}
        if any(a.split("=", 1)[0] in forbidden for a in args):
            # Only the local authority preparation for the distinct negative
            # may name a private origin; never a tested customer lookup.
            negative_setup = args[:3] == ("id", "namespace", "prepare-controller") and "https://private-registry.adaz.test:8010" in args
            if not negative_setup:
                raise ValueError("customer command has an endpoint or policy override")
        environment = {"HOME": str(self.homes[actor]), "PATH": "/usr/local/bin:/usr/bin:/bin", "NO_COLOR": "1"}
        result = subprocess.run([str(self.binary), "--json", *args], cwd=self.homes[actor] / "workspace",
                                env=environment, capture_output=True, text=True, timeout=45)
        with (self.work / "commands.private.jsonl").open("a") as stream:
            stream.write(json.dumps({"actor": actor, "args": args, "exit": result.returncode,
                                     "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        if success:
            if result.returncode:
                raise AssertionError("real published CLI command failed; see private command receipt")
            return json.loads(result.stdout)
        return result

    def dns_ready(self, actor):
        end = time.monotonic() + 15
        while True:
            checked = self.command(actor, "id", "namespace", "check-txt", "--domain", DOMAINS[actor], success=False)
            if checked.returncode == 0:
                return
            if time.monotonic() >= end:
                raise AssertionError("actual namespace TXT was not observed")
            time.sleep(0.2)

    def onboarding_and_mail(self):
        # prepare-controller is LOCAL ONLY. The real first default-registry
        # write below, and its service request receipts, establish the path.
        for actor, domain in DOMAINS.items():
            prepared = self.command(actor, "id", "namespace", "prepare-controller", "--domain", domain)
            self.records[domain] = prepared["dns_value"]
        write_zone(self.work / "dns/authority.zone", self.public_ip, self.records)
        for actor, domain in DOMAINS.items():
            self.dns_ready(actor)
            identity = self.command(actor, "id", "create", "--domain", domain, "--name", actor, "--root-parent")
            assert identity["address"] == domain + "/" + actor
            assert identity["did_key"].startswith("did:key:") and identity["did_aw"].startswith("did:aw:")
            self.bindings[actor] = identity
        domain = DOMAINS["alice"]
        team = self.command("alice", "id", "team", "create", "--namespace", domain, "--name", "members")
        team_id = "members:" + domain
        assert team["team_id"] == team_id
        for actor, identity in self.bindings.items():
            added = self.command("alice", "id", "team", "add-member", "--namespace", domain, "--team", "members",
                                 "--did", identity["did_key"], "--alias", actor, "--global",
                                 "--did-aw", identity["did_aw"], "--address", identity["address"])
            fetched = self.command(actor, "id", "team", "fetch-cert", "--namespace", domain,
                                   "--team", "members", "--cert-id", added["certificate_id"])
            assert fetched["status"] == "installed"
        registered = self.command("alice", "id", "team", "register", "--team", team_id, "--service", SERVICE)
        assert registered["status"] == "created"
        for actor in self.bindings:
            self.command(actor, "service", "init", "--service", SERVICE, "--team", team_id)
            status = self.command(actor, "workspace", "status")
            assert status["active_team"] == team_id
            # Keep the complete actual status private; team/custody are not
            # inferred from a successful connection alone.
            (self.work / (actor + "-status.json")).write_text(json.dumps(status, indent=2))
        body = "published-default-registry-ordinary-mail"
        sent = self.command("alice", "mail", "send", "--plaintext", "--to", "bob", "--subject", "ADA Z default", "--body", body)
        inbox = self.command("bob", "mail", "inbox", "--show-all")
        message = next(m for m in inbox["messages"] if m["message_id"] == sent["message_id"])
        assert message["body"] == body
        reply = self.command("bob", "mail", "reply", sent["message_id"], "--body", "default-registry-reply")
        returned = self.command("alice", "mail", "inbox", "--show-all")
        message = next(m for m in returned["messages"] if m["message_id"] == reply["message_id"])
        assert message["body"] == "default-registry-reply"
        assert message["conversation_id"] == sent["conversation_id"]
        resolved = self.command("reader", "id", "namespace", "resolve", self.bindings["alice"]["address"])
        assert self.bindings["alice"]["did_aw"] in json.dumps(resolved)
        self.outcomes["default_onboarding_and_mail"] = "PASS"

    def quota(self):
        result = exercise(REGISTRY, DOMAINS["alice"], self.bindings["alice"]["did_aw"],
                          self.public_ip, self.work / "quota.json")
        assert result["verdict"] == "PASS", "real quota exercise failed; no retry"
        self.outcomes["real_namespace_quota_and_did_neighbor"] = "PASS"

    def private_origin_negative(self):
        # Use the real namespace controller's LOCAL command to publish an
        # alternate DNS locator. The reader has no registry override or pin.
        domain = DOMAINS["alice"]
        prepared = self.command("alice", "id", "namespace", "prepare-controller", "--domain", domain,
                                "--registry", "https://private-registry.adaz.test:8010")
        self.records[domain] = prepared["dns_value"]
        write_zone(self.work / "dns/authority.zone", self.public_ip, self.records)
        end = time.monotonic() + 15
        while True:
            checked = self.command("alice", "id", "namespace", "check-txt", "--domain", domain)
            if checked["registry_url"] == "https://private-registry.adaz.test:8010":
                break
            assert time.monotonic() < end, "negative DNS locator did not become visible"
            time.sleep(0.2)
        result = self.command("negative", "id", "namespace", "resolve", self.bindings["alice"]["address"], success=False)
        assert result.returncode != 0 and "not public" in result.stdout + result.stderr
        self.outcomes["dns_private_origin_refusal"] = "PASS"


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--public-ip", required=True)
    args = parser.parse_args()
    addresses = {a[4][0] for a in socket.getaddrinfo("api.awid.ai", 443, type=socket.SOCK_STREAM)}
    assert addresses == {args.public_ip}, "normal client DNS differs from actual assigned address"
    journey = Journey(args.work, args.public_ip)
    receipt = {"binary_sha256": BINARY_SHA256, "source_repository": "github.com/awebai/aw",
               "source_sha": SOURCE_SHA, "version": VERSION, "dns_addresses": sorted(addresses), "verdict": "FAIL"}
    try:
        journey.onboarding_and_mail()
        journey.quota()
        journey.private_origin_negative()
        receipt["verdict"] = "PASS"
    finally:
        receipt["outcomes"] = journey.outcomes
        (args.work / "client-result.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()

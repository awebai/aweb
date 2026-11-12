"""The protected round trip, one body for every place it runs.

One human-role.revoke goes through the independent protected server
(aweb.protected_signing.host, HOST.md): the requester's aw prepares it, the
approving human logs in on the console page in a fresh Chromium tab with a
passkey and approves the exact act with a separate user verification, the
server signs with the team controller key only it holds, and aw reports the
exact committed receipt. Then the refusals: no user verification signs
nothing, a changed act is refused, and a lost prepare answer is completed
from its receipt with one signature.

The body runs in the secrets e2e lane (tests/test_e2e_protected_revoke.py)
and in the team deployment journey (scripts/e2e/team_deployment_journey.py).
Each supplies a Site: where its machines and files are and how its signer is
configured, provisioned, started and reached. Provisioning follows HOST.md
through B3's own enrolment APIs; nothing inserts a credential, session or
success row.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

import pexpect
from awid.did import did_key_from_signing_key
from awid.signing import load_signing_key_pem


def docker(*args: str, timeout: int = 120, input: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], text=True, capture_output=True, timeout=timeout, input=input, check=False)


def first_json(text: str):
    """The first JSON value in a command's output; Docker may print hints after it."""
    return json.JSONDecoder().raw_decode(text[text.index("{"):])[0]


def aw(container: str, *args: str, env: dict[str, str] | None = None) -> dict:
    """Run aw --json in a machine, without a terminal, and return its JSON."""
    extra = [f"--env={k}={v}" for k, v in (env or {}).items()]
    result = docker("exec", *extra, container, "aw", "--json", *args, timeout=300)
    assert result.returncode == 0, f"aw {' '.join(args)}\n{result.stdout}\n{result.stderr}"
    return first_json(result.stdout)


def aw_refused(container: str, *args: str, env: dict[str, str] | None = None) -> str:
    """Run aw --json expecting a refusal; return its error code."""
    extra = [f"--env={k}={v}" for k, v in (env or {}).items()]
    result = docker("exec", *extra, container, "aw", "--json", *args, timeout=300)
    assert result.returncode != 0, result.stdout
    return first_json(result.stdout)["error"]["code"]


def await_awid_txt(machine: str, domain: str, controller_did: str) -> None:
    """Wait, bounded, until the machine's resolver sees the published
    controller: the zone is reloaded once a second, so a lookup made at once
    can still return the previous record."""
    for _ in range(30):
        answer = docker("exec", machine, "nslookup", "-type=txt", f"_awid.{domain}")
        if controller_did in answer.stdout:
            return
        time.sleep(0.5)
    raise AssertionError(f"_awid.{domain} never named {controller_did}")


class Holder:
    """The holder's machine: aw with a human key in its own Secret Service."""

    def __init__(self, container: str, domain: str) -> None:
        self.container, self.domain = container, domain
        # A disposable passphrase, generated now and never printed or stored.
        self.passphrase = secrets.token_urlsafe(24)
        # The session bus and the keyring's files and sockets live on the
        # container's own filesystem: on the runtime bind mount gnome-keyring
        # leaves the login collection locked, and once it drops its
        # capabilities it cannot write a home the host user owns.
        # aw reaches the keyring only over this bus.
        self.bus = "unix:path=/tmp/holder-session.bus"
        keyring = (
            "XDG_RUNTIME_DIR=/tmp/holder-runtime XDG_DATA_HOME=/tmp/holder-keyring "
            "DBUS_SESSION_BUS_ADDRESS=" + self.bus
        )
        # -i: without it docker exec attaches no stdin and the unlock reads no
        # password. The other daemons get /dev/null, so only the unlock reads it.
        started = docker(
            "exec", "-i", container, "sh", "-c",
            "umask 077 && mkdir -p /tmp/holder-keyring /tmp/holder-runtime "
            "&& dbus-daemon --session --fork --address=" + self.bus + " </dev/null "
            "&& " + keyring + " gnome-keyring-daemon --unlock --components=secrets "
            "&& " + keyring + " gnome-keyring-daemon --start --components=secrets </dev/null",
            input=secrets.token_urlsafe(24),
        )
        assert started.returncode == 0, started.stdout + started.stderr

    def act(self, principal: str, *args: str) -> pexpect.spawn:
        """aw as the holder for a command that a holder-signed start begins.

        This is the one place that chooses how the holder authenticates. Today
        it is the existing --human participation (the human key in this
        machine's Secret Service, unlocked at the terminal). The protected
        profile (package 1 rule (b)) replaces only this method: a restricted
        requester credential, a B3 UV login at the protected service, and the
        server's holder-signed start. The H acceptance (acxy.9/11) runs there.
        """
        return self.spawn("--human", principal, "--human-domain", self.domain, *args)

    def spawn(self, *args: str) -> pexpect.spawn:
        """aw on the holder's terminal: docker exec -it gives it a real PTY."""
        return pexpect.spawn(
            "docker",
            ["exec", "-it", f"--env=DBUS_SESSION_BUS_ADDRESS={self.bus}", self.container, "aw", *args],
            encoding="utf-8", timeout=180, echo=False,
        )

    def answer_passphrases(self, child: pexpect.spawn, *, until: str | None = None) -> str:
        """Type the passphrase at each prompt, never logging it; return the output."""
        seen = []
        patterns = [r"Choose a passphrase[^\r\n]*: ", r"Type the passphrase again: ", r"Passphrase for that human key: "]
        if until:
            patterns.append(until)
        patterns.append(pexpect.EOF)
        while True:
            found = child.expect(patterns)
            seen.append(child.before)
            if child.match is pexpect.EOF or (until and found == len(patterns) - 2):
                if until and found == len(patterns) - 2:
                    seen.append(child.match.group(0))
                return "".join(seen)
            child.sendline(self.passphrase)


@dataclass
class Site:
    """Where one round trip runs. ``runtime`` is the host directory every
    machine and the Chromium driver mount at ``mounted``; a machine's HOME is
    ``mounted``/its name."""

    runtime: Path
    mounted: str
    domain: str
    team: str
    registry: str
    aweb: str
    signer: str
    human: str
    service_id: str
    app_id: str
    role: str
    contact: str
    # The captured notification transport's API, as a machine reaches it.
    mail_api: str
    # The operator profile, as aw in the holder's machine reads it.
    profile_in_machine: str
    publish_controller: Callable[[str], None]
    # The signer's ordinary member key (aw's PEM file) and its custody of the
    # team controller seed (64 hex characters), each stored where only it reads.
    store_member: Callable[[str], None]
    store_controller: Callable[[str], None]
    # The operator profile and scope, and the process configuration.
    configure_signer: Callable[[dict, dict], None]
    # provision.py inside the signer's container, as its uid; returns its JSON.
    provision: Callable[..., dict]
    start_signer: Callable[[], None]
    # The approving human's Chromium in a machine's network namespace.
    chromium: Callable[..., dict]
    # While on, the front drops the answer of a committed prepare once.
    drop_prepare_answers: Callable[[bool], None]

    @property
    def team_id(self) -> str:
        return f"{self.team}:{self.domain}"

    @property
    def rp_id(self) -> str:
        return self.human.removeprefix("https://")


@dataclass(frozen=True)
class Founded:
    """The namespace, its root human (the approver) and the team, and the
    requester: a root-parented agent identity of the team, connected to aweb."""

    controller_did: str
    approver: str
    requester: str
    requester_did_key: str


def found_team(site: Site, holder: Holder) -> Founded:
    """The namespace, its root human H and the team, on H's machine. The same
    machine holds the namespace controller, so aw creates the root-parented
    requester there, beside H's human key."""
    machine = holder.container
    prepared = aw(machine, "id", "namespace", "prepare-controller", "--domain", site.domain, "--registry", site.registry)
    site.publish_controller(prepared["controller_did"])
    await_awid_txt(machine, site.domain, prepared["controller_did"])
    child = holder.spawn("--json", "id", "human", "init", "--domain", site.domain, "--as-root")
    output = holder.answer_passphrases(child)
    child.close()
    assert child.exitstatus == 0, output
    approver = first_json(output)["id"]
    aw(machine, "id", "team", "create", "--name", site.team, "--namespace", site.domain, "--registry", site.registry)
    created = aw(machine, "id", "create", "--name", "owner", "--domain", site.domain, "--root-parent",
                 "--registry", site.registry)
    invite = aw(machine, "id", "team", "invite", "--team", site.team, "--namespace", site.domain, "--member-global")
    aw(machine, "id", "team", "accept-invite", invite["token"], "--name", "owner", "--global")
    aw(machine, "init", "--url", site.aweb, "--name", "owner", "--do-not-touch-agents-md")
    return Founded(prepared["controller_did"], approver, created["did_aw"], created["did_key"])


def enrolment_token(site: Site, machine: str) -> str:
    """The approver's enrolment link, read from the captured transport."""
    listing = docker("exec", machine, "curl", "-fsS", f"{site.mail_api}/api/v1/messages")
    assert listing.returncode == 0, listing.stderr
    messages = [m for m in json.loads(listing.stdout)["messages"] if any(t["Address"] == site.contact for t in m["To"])]
    assert len(messages) == 1, messages
    message = docker("exec", machine, "curl", "-fsS", f"{site.mail_api}/api/v1/message/{messages[0]['ID']}")
    link = re.search(re.escape(site.human) + r"/enrolment#token=(\S+)", json.loads(message.stdout)["Text"])
    assert link, message.stdout
    return unquote(link.group(1))


def provision_signer(site: Site, holder: Holder, founded: Founded) -> None:
    """Configure, provision and start the signer, and enrol the approver's
    passkey with Chromium's own attestation on the human origin."""
    machine = holder.container
    # The protected server's ordinary member credential (never the controller):
    # aw creates the key in the member's own identity.
    home = f"{site.mounted}/protected-reader"
    (site.runtime / "protected-reader" / "identity").mkdir(parents=True, mode=0o700)
    requested = first_json(docker("exec", "-e", f"HOME={home}", "-w", f"{home}/identity", machine, "aw", "--json",
                                  "id", "team", "request", "--create-local-key", "--team", site.team_id,
                                  "--name", "protected-reader", timeout=300).stdout)
    added = aw(machine, "id", "team", "add-member", "--team", site.team, "--namespace", site.domain,
               "--did", requested["did_key"], "--name", "protected-reader", "--global")
    assert added["certificate_id"]
    site.store_member((site.runtime / "protected-reader" / "identity" / ".aw" / "signing.key").read_text())

    # Team administration is done: the controller key leaves the holder's
    # machine for the protected server's custody.
    team_key = site.runtime / "holder" / ".awid" / "team-keys" / site.domain / f"{site.team}.key"
    seed = load_signing_key_pem(team_key.read_bytes())
    team_key.unlink()
    site.store_controller(seed.hex())

    # The operator profile, its one binding, and the process configuration.
    scope = {"v": 1, "kind": "protected_key", "service_id": site.service_id,
             "authority": {"kind": "team_controller", "id": site.team_id, "domain": site.domain},
             "human": {"id": founded.approver, "domain": site.domain}, "generation": 1}
    profile = {
        "v": 1, "service_id": site.service_id, "request_origin": site.signer, "human_origin": site.human,
        "rp_id": site.rp_id, "registry_origin": site.registry,
        "namespace_authorities": [{"domain": site.domain, "controller_did": founded.controller_did}],
        "bindings": [{"scope": scope, "authority_key_did": did_key_from_signing_key(seed),
                      "policy": {"ref": "aweb.human-assurance/1", "version": 1}}],
    }
    site.configure_signer(profile, scope)

    # HOST.md provisioning: declared rows, then B3 enrolment with the
    # browser's own attestation on the human origin.
    site.provision("setup", "--human-id", founded.approver, "--requester", founded.requester, "--contact", site.contact)
    token = enrolment_token(site, machine)
    options = site.provision("options", "--token", token)
    (site.runtime / "enrolment-options.json").write_text(json.dumps(options))
    site.start_signer()
    site.chromium(machine, "enrol", "--origin", site.human, "--options", f"{site.mounted}/enrolment-options.json",
                  "--attestation", f"{site.mounted}/attestation.json", "--device", f"{site.mounted}/approver-device.json")
    site.provision("complete", "--token", token, stdin=(site.runtime / "attestation.json").read_text())


def start_revoke(site: Site, machine: str, principal: str) -> tuple[pexpect.spawn, str, str, str]:
    """aw prepares the revoke as the requester; returns the page it names, the
    operation id and the digest it printed."""
    child = pexpect.spawn(
        "docker", ["exec", "-it", machine, "aw", "--json", "app", "role", "revoke", site.app_id, "--role", site.role,
                   "--principal", principal, "--protected-profile", site.profile_in_machine, "--approver", principal],
        encoding="utf-8", timeout=180, echo=False,
    )
    child.expect(r"Operation (\S+)\r?\n\s+digest:\s+([0-9a-f]{64})")
    operation, digest = child.match.group(1), child.match.group(2)
    child.expect(r"Approve it on this page: (\S+)")
    page = child.match.group(1)
    assert page.startswith(site.human + "/handoff/"), page
    return child, page, operation, digest


def finish(child: pexpect.spawn) -> tuple[int, str]:
    child.expect(pexpect.EOF, timeout=240)
    output = child.before
    child.close()
    return child.exitstatus, output


def approve(site: Site, machine: str, page: str, *uv: str) -> dict:
    return site.chromium(machine, "approve", "--url", page, "--device", f"{site.mounted}/approver-device.json", *uv)


def round_trip(site: Site, holder: Holder, founded: Founded) -> str:
    """aw prepares, the page logs the human in, then the human approves the
    exact act aw printed, and aw reports its receipt. Returns the operation."""
    machine, approver = holder.container, founded.approver
    saved = site.runtime / "holder" / ".config" / "aw" / "governance"
    child, page, operation, digest = start_revoke(site, machine, approver)
    report = approve(site, machine, page)
    assert report["states"] == ["login-required", "ready", "navigated"], report
    assert report["digest"] == digest and report["act"] == "human-role.revoke", report
    status, output = finish(child)
    assert status == 0, output
    receipt = first_json(output)
    assert (receipt["operation_id"], receipt["state"]) == (operation, "committed"), receipt
    assert site.provision("evidence", "--operation-id", operation)[operation] == {"signed": True, "refusal_code": None}
    assert not (saved / f"{operation}.json").exists(), "a committed operation's saved request remains"
    return operation


def refusals(site: Site, holder: Holder, founded: Founded) -> None:
    """The essential refusals, each with what was and was not signed."""
    machine, approver = holder.container, founded.approver
    saved = site.runtime / "holder" / ".config" / "aw" / "governance"

    # No user verification, at the login and then at the approval: nothing
    # is signed, and the operation stays pending with its saved request.
    pending = []
    for phase in ("login", "approve"):
        child, page, operation, _ = start_revoke(site, machine, approver)
        report = approve(site, machine, page, f"--{phase}-uv", "no")
        assert "navigated" not in report["states"], report
        assert report["states"][-1] == ("login-required" if phase == "login" else "ready"), report
        child.sendintr()
        finish(child)
        assert site.provision("evidence", "--operation-id", operation)[operation]["signed"] is False
        assert (saved / f"{operation}.json").exists()
        pending.append(operation)

    # A changed act under the same operation id: a validly encoded intent
    # with another role, resent from aw's saved request. The service refuses
    # operation_conflict and signs nothing.
    changed = pending[0]
    record = json.loads((saved / f"{changed}.json").read_text())
    body = json.loads(base64.b64decode(record["body"]))
    body["subject"]["role"] = site.role + "-other"
    record["body"] = base64.b64encode(json.dumps(body, separators=(",", ":"), sort_keys=True).encode()).decode()
    (saved / f"{changed}.json").write_text(json.dumps(record))
    refused = docker("exec", machine, "aw", "--json", "app", "role", "resume", changed,
                     "--protected-profile", site.profile_in_machine)
    assert refused.returncode != 0, refused.stdout
    assert first_json(refused.stdout)["error"]["code"] == "operation_conflict", refused.stdout
    assert site.provision("evidence", "--operation-id", changed)[changed]["signed"] is False

    # A lost prepare answer: the front drops the committed prepare's
    # response once. aw reads the receipt instead of preparing again, keeps
    # the request, and the resume completes the original operation with one
    # signature.
    site.drop_prepare_answers(True)
    try:
        lost = docker("exec", machine, "aw", "--json", "app", "role", "revoke", site.app_id, "--role", site.role,
                      "--principal", approver, "--protected-profile", site.profile_in_machine, "--approver", approver,
                      timeout=240)
    finally:
        site.drop_prepare_answers(False)
    assert lost.returncode != 0, lost.stdout
    assert first_json(lost.stdout)["error"]["code"] == "prepare_unconfirmed", lost.stdout
    operation = re.search(r"Preparing operation (\S+)", lost.stderr).group(1)
    assert (saved / f"{operation}.json").exists()
    child = pexpect.spawn("docker", ["exec", "-it", machine, "aw", "--json", "app", "role", "resume", operation,
                                     "--protected-profile", site.profile_in_machine],
                          encoding="utf-8", timeout=180, echo=False)
    child.expect(r"Approve it on this page: (\S+)")
    report = approve(site, machine, child.match.group(1))
    assert report["states"] == ["login-required", "ready", "navigated"], report
    status, output = finish(child)
    assert status == 0, output
    receipt = first_json(output)
    assert (receipt["operation_id"], receipt["state"]) == (operation, "committed"), receipt
    assert site.provision("evidence", "--operation-id", operation)[operation] == {"signed": True, "refusal_code": None}

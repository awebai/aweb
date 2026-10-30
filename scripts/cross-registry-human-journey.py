"""Real aw + Secret Service + terminal journey, inside the CLI container."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

import pexpect
import yaml

ROOT = Path("/work")
# Synthetic fixture input, typed into /dev/tty. Never argv or environment.
PASSPHRASE = "disposable journey human passphrase"


def barrier(name):
    (ROOT / (name + "-request")).touch()
    deadline = time.monotonic() + 120
    while not (ROOT / (name + "-complete")).exists():
        if time.monotonic() >= deadline:
            raise AssertionError("fixture service barrier timed out: " + name)
        time.sleep(0.1)


def command(args, *, cwd="alice", fail_registration=False, json_output=True,
            confirmation=None, fingerprint=None):
    child = pexpect.spawn("aw", args, cwd=str(ROOT / cwd), encoding="utf-8", timeout=120, echo=False)
    transcript = []
    prompts = 0
    confirmations = 0
    while True:
        found = child.expect([r"Choose a passphrase[^\r\n]*: ", r"Type the passphrase again: ",
                              r"Passphrase for that human key: ",
                              r"Fingerprint ([0-9a-f-]+)\. Does it match what [^\r\n]*\? \[y/N\] ",
                              pexpect.EOF])
        transcript.append(child.before)
        if found == 4:
            break
        if found == 3:
            assert confirmation in ("y", "n") and child.match.group(1) == fingerprint
            confirmations += 1
            child.sendline(confirmation)
            continue
        prompts += 1
        if fail_registration and found == 2:
            # Issuer status was obtained before this prompt. Stop the real
            # service before releasing the signature, not on a guessed timer.
            barrier("stop-awid")
        child.sendline(PASSPHRASE)
    child.close()
    text = "".join(transcript)
    if confirmation is not None:
        assert confirmations == 1, text
    if confirmation == "n":
        assert child.exitstatus != 0 and "human_approval_required" in text, text
        return None
    if fail_registration:
        assert child.exitstatus != 0, text
        assert "register the certificate" in text, text
        return None
    assert child.exitstatus == 0, text
    if not json_output:
        return text, prompts
    start = text.find("{")
    assert start >= 0, text
    return json.loads(text[start:]), prompts


def wait_file(name):
    path = ROOT / "csr" / name
    deadline = time.monotonic() + 180
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError("CSR transport timed out: " + name)
        time.sleep(0.1)
    return path


def publish_csr(name, text):
    path = ROOT / "csr" / name
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text)
    temporary.replace(path)


def csr_requester():
    """Separate CLI container, HOME and D-Bus keyring; public files transport."""
    human, prompts = command(["id", "human", "init", "--domain", "alpha.example.com", "--json"])
    assert human["status"] == "prepared" and prompts == 2, human
    human_home, = (Path.home() / ".awid/humans/alpha.example.com").glob("*")
    record = yaml.safe_load((human_home / "identity.yaml").read_text())
    assert record["state"] == "prepared" and not (human_home / "id-chain.json").exists()
    publish_csr("prepared.json", json.dumps(human))
    invitation = json.loads(wait_file("invitation.json").read_text())
    text, prompts = command(["id", "parent", "request", "--invitation-id", invitation["invitation_id"],
                             "--domain", "alpha.example.com", "--root-parent", "--human", human["id"],
                             "--out", "/work/csr/request.json"], json_output=False)
    assert prompts == 1, text
    fingerprint, = re.findall(r"different trusted channel: ([0-9a-f-]+)", text)
    # The driver conveys the requester's displayed fingerprint independently
    # of the CSR file, and compares it with the issuer's displayed value.
    publish_csr("fingerprint.txt", fingerprint)
    wait_file("response-ready")
    imported, prompts = command(["id", "parent", "import", "/work/csr/response.json", "--human", human["id"],
                                "--domain", "alpha.example.com", "--json"])
    assert imported["registration"] == "registered" and prompts == 2, imported
    record = yaml.safe_load((human_home / "identity.yaml").read_text())
    assert record["state"] == "registered", record
    outgoing, = (human_home / "requests").glob("*.json")
    request = json.loads(outgoing.read_text())
    assert request["state"] == "imported" and request["registration"] == "registered", request
    assert request["invitation_id"] == invitation["invitation_id"]
    assert json.loads(request["request"])["request"]["invitation_id"] == invitation["invitation_id"]
    assert request["response"] == (ROOT / "csr/response.json").read_text()
    publish_csr("complete.json", json.dumps(public_case(human_home, record, kind="human", human=human["id"])))
    print("PASS: CSR requester prepare, export and root-issued import register the same invitation", flush=True)


def csr_root():
    prepared = json.loads(wait_file("prepared.json").read_text())
    # Prepare-only really made no registry identity, before invitation/export.
    import urllib.error
    import urllib.request
    try:
        urllib.request.urlopen("http://awid-a:8010/v1/did/" + prepared["id"] + "/key", timeout=5)
    except urllib.error.HTTPError as exc:
        assert exc.code == 404, exc
    else:
        raise AssertionError("prepare-only human already registered")
    root = ["--as-root", "--domain", "alpha.example.com"]
    invitation, _ = command(["id", "child", "invite", *root, "--kind", "human",
                              "--recipient", "fixture requester", "--json"])
    publish_csr("invitation.json", json.dumps(invitation))
    request = json.loads(wait_file("request.json").read_text())
    fingerprint = wait_file("fingerprint.txt").read_text()
    request_id = request["request"]["request_id"]
    received, _ = command(["id", "child", "receive", "/work/csr/request.json", *root, "--json"])
    assert received["state"] == "pending" and received["fingerprint"] == fingerprint, received
    issuance = Path.home() / ".awid/controllers/alpha.example.com.id-issuance"
    before = {p.name: p.read_bytes() for p in issuance.glob("*.json")}
    approve = ["id", "child", "approve", request_id, *root, "--out", "/work/csr/response.json"]
    command(approve, json_output=False, confirmation="n", fingerprint=fingerprint)
    assert not (ROOT / "csr/response.json").exists()
    assert {p.name: p.read_bytes() for p in issuance.glob("*.json")} == before
    pending, _ = command(["id", "child", "show", request_id, *root, "--json"])
    assert pending["state"] == "pending" and not pending.get("certificate_id"), pending
    assert pending["invitation_void"] is False, pending
    print("PASS: declined CSR fingerprint approval signs nothing and leaves the request pending", flush=True)
    command(approve, json_output=False, confirmation="y", fingerprint=fingerprint)
    after = {p.name: p.read_bytes() for p in issuance.glob("*.json")}
    assert len(after) == len(before) + 1
    publish_csr("response-ready", "")
    print("PASS: root CSR approval accepts the matching fingerprint through a real PTY", flush=True)
    return json.loads(wait_file("complete.json").read_text())


def public_case(home, record, *, kind, human=""):
    return dict(Home=str(home), ID=record["stable_id"], DIDKey=record["did_key"],
                Domain=record["domain"], Outcome="nearest_human" if human else "no_human",
                HumanID=human, Kind=kind, Bundle=json.loads((home / "id-chain.json").read_text()))


def main():
    assert not os.environ.get("AWID_SKIP_DNS_VERIFY")
    assert os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    if "--csr-requester" in sys.argv:
        csr_requester()
        return
    if os.environ.get("AWEB_CROSS_REGISTRY_CSR") == "1":
        for group in ("child", "parent"):
            help_text = subprocess.check_output(["aw", "id", group, "--help"], text=True)
            assert ("invite" if group == "child" else "request") in help_text
    human, prompts = command(["id", "human", "init", "--domain", "alpha.example.com", "--as-root", "--json"])
    assert human["status"] == "registered" and prompts == 4, human
    human_home, = (Path.home() / ".awid/humans/alpha.example.com").glob("*")
    human_record = yaml.safe_load((human_home / "identity.yaml").read_text())
    assert human_record["stable_id"] == human["id"]
    print("PASS: namespace, root human issuance and human certificate registration through real Secret Service + PTY", flush=True)

    args = ["id", "create", "--name", "alice", "--domain", "alpha.example.com",
            "--human-parent", human["id"], "--json"]
    command(args, fail_registration=True)
    identity_path = ROOT / "alice/.aw/identity.yaml"
    before_identity = identity_path.read_bytes()
    before_key = (identity_path.parent / "signing.key").read_bytes()
    entries = list((human_home / "id-issuance").glob("*.json"))
    assert len(entries) == 1, entries
    entry_bytes = entries[0].read_bytes()
    entry = json.loads(entry_bytes)
    assert not (identity_path.parent / "id-chain.json").exists()
    barrier("start-awid")
    resumed, prompts = command(args)
    assert resumed["status"] == "chain_installed" and prompts == 0, resumed
    assert identity_path.read_bytes() == before_identity
    assert (identity_path.parent / "signing.key").read_bytes() == before_key
    assert list((human_home / "id-issuance").glob("*.json")) == entries
    assert entries[0].read_bytes() == entry_bytes
    alice_bundle = json.loads((identity_path.parent / "id-chain.json").read_text())
    assert alice_bundle["certificates"][-1] == entry["signed"]
    print("PASS: failed agent certificate registration resumes unchanged with one issuance entry", flush=True)

    (ROOT / "fresh").mkdir()
    fresh, prompts = command(["id", "create", "--name", "fresh", "--domain", "alpha.example.com",
                              "--human-parent", human["id"], "--json"], cwd="fresh")
    assert fresh["human_parent"] == human["id"] and prompts == 1
    print("PASS: fresh --human-parent issuance and agent certificate registration", flush=True)

    bob, prompts = command(["id", "create", "--name", "bob", "--domain", "beta.example.net",
                            "--root-parent", "--json"], cwd="bob")
    assert bob["root_parent"] and prompts == 0, bob
    print("PASS: --root-parent issuance and agent certificate registration", flush=True)

    cases = [public_case(human_home, human_record, kind="human", human=human["id"])]
    for name, parent in [("alice", human["id"]), ("fresh", human["id"]), ("bob", "")]:
        home = ROOT / name / ".aw"
        record = yaml.safe_load((home / "identity.yaml").read_text())
        # Worktree identities encode DID as did, while human records use did_key.
        record["did_key"] = record["did"]
        record["domain"] = "beta.example.net" if name == "bob" else "alpha.example.com"
        cases.append(public_case(home, record, kind="agent", human=parent))
    if os.environ.get("AWEB_CROSS_REGISTRY_CSR") == "1":
        cases.append(csr_root())
    (ROOT / "journey-public.json").write_text(json.dumps(cases))
    (ROOT / "alice-create.json").write_text(json.dumps(resumed))
    (ROOT / "bob-create.json").write_text(json.dumps(bob))


if __name__ == "__main__":
    # Secret Service is a real D-Bus service, shared by all aw processes in
    # this session. Its disposable collection has no developer credentials.
    runtime = Path("/tmp/journey-runtime")
    runtime.mkdir(mode=0o700, exist_ok=True)
    os.environ["XDG_RUNTIME_DIR"] = str(runtime)
    subprocess.run(["gnome-keyring-daemon", "--unlock", "--components=secrets"],
                   input=b"disposable collection password", check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["gnome-keyring-daemon", "--start", "--components=secrets"],
                   check=True, stdout=subprocess.DEVNULL)
    main()

"""Real aw + Secret Service + terminal journey, inside the CLI container."""
import json
import os
from pathlib import Path
import subprocess
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


def command(args, *, cwd="alice", fail_registration=False):
    child = pexpect.spawn("aw", args, cwd=str(ROOT / cwd), encoding="utf-8", timeout=120, echo=False)
    transcript = []
    prompts = 0
    while True:
        found = child.expect([r"Choose a passphrase[^\r\n]*: ", r"Type the passphrase again: ",
                              r"Passphrase for that human key: ", pexpect.EOF])
        transcript.append(child.before)
        if found == 3:
            break
        prompts += 1
        if fail_registration and found == 2:
            # Issuer status was obtained before this prompt. Stop the real
            # service before releasing the signature, not on a guessed timer.
            barrier("stop-awid")
        child.sendline(PASSPHRASE)
    child.close()
    text = "".join(transcript)
    if fail_registration:
        assert child.exitstatus != 0, text
        assert "register the certificate" in text, text
        return None
    assert child.exitstatus == 0, text
    start = text.find("{")
    assert start >= 0, text
    return json.loads(text[start:]), prompts


def public_case(home, record, *, kind, human=""):
    return dict(Home=str(home), ID=record["stable_id"], DIDKey=record["did_key"],
                Domain=record["domain"], Outcome="nearest_human" if human else "no_human",
                HumanID=human, Kind=kind, Bundle=json.loads((home / "id-chain.json").read_text()))


def main():
    assert not os.environ.get("AWID_SKIP_DNS_VERIFY")
    assert os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    human, prompts = command(["id", "human", "init", "--domain", "alpha.example.com", "--as-root", "--json"])
    assert human["status"] == "registered" and prompts == 4, human
    human_home, = (Path.home() / ".awid/humans/alpha.example.com").glob("*")
    human_record = yaml.safe_load((human_home / "identity.yaml").read_text())
    assert human_record["stable_id"] == human["id"]
    print("PASS: namespace, root human issuance and human certificate registration through real Secret Service + PTY", flush=True)

    args = ["id", "create", "--name", "alice", "--domain", "alpha.example.com",
            "--parent-human", human["id"], "--json"]
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
                              "--parent-human", human["id"], "--json"], cwd="fresh")
    assert fresh["parent_human"] == human["id"] and prompts == 1
    print("PASS: fresh --parent-human issuance and agent certificate registration", flush=True)

    bob, prompts = command(["id", "create", "--name", "bob", "--domain", "beta.example.net",
                            "--parent-root", "--json"], cwd="bob")
    assert bob["parent_root"] and prompts == 0, bob
    print("PASS: --parent-root issuance and agent certificate registration", flush=True)

    cases = [public_case(human_home, human_record, kind="human", human=human["id"])]
    for name, parent in [("alice", human["id"]), ("fresh", human["id"]), ("bob", "")]:
        home = ROOT / name / ".aw"
        record = yaml.safe_load((home / "identity.yaml").read_text())
        # Worktree identities encode DID as did, while human records use did_key.
        record["did_key"] = record["did"]
        record["domain"] = "beta.example.net" if name == "bob" else "alpha.example.com"
        cases.append(public_case(home, record, kind="agent", human=parent))
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

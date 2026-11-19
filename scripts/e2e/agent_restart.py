"""An agent container keeps its seat across a restart and a replacement.

    python3 -I scripts/e2e/agent_restart.py --evidence DIR --container NAME \\
        --state-dir DIR --uid UID --gid GID --seat ALIAS --ssh-config FILE \\
        --image-id sha256:... --compose "docker compose -p ... -f ..." \\
        --peer-aw PATH --peer-home DIR

Run as root on the engine host, against a running OATS agent container
(OATS container/agent/compose.agent.yaml) whose seat was admitted on the
supported route (OATS docs/container.md, "Making a seat"). Root reads the
state directory itself; nothing is read inside the container but over the
operator's SSH, whose host key is pinned in --ssh-config.

docker and docker compose go to the local daemon's socket alone, with no
inherited context or configuration.

Before anything changes, it records the container, the seat's and the
peer's did:key (the peer is an identity outside the container), a probe the
seat writes over SSH, and a snapshot of the state. The bound state must then
hold that very probe, byte for byte (so SSH reached this state), the seat's
member key, a certificate and sshd's private host key; a walk that cannot
read an entry stops. Then two cases, each judged on its own:

1. restart: docker restart of the inspected container (same id);
2. replace: the Compose project must name exactly one agent container, the
   one inspected; that id alone is stopped and removed, its absence is
   observed in a clean listing, and only then does the given Compose command
   create the agent again (a new id), with the same image and /state source.

After each, and once before: the container is healthy, SSH still accepts
the pinned host key, the seat answers with the same did:key, the snapshot
shows no drift (the same keys, certificate and probe, the same modes, every
entry the agents' own), and a signed round trip passes: the peer sends, the
seat finds that message by the send receipt's id, from the peer, verified;
the seat replies with its own key, and the peer finds that reply, from the
seat, verified. The probe and the snapshot show no key or file content:
digests of secrets stay in memory and only their equality is written.

Exit 0 only when every check of both cases passed; the evidence directory
holds one JSON file per step and result.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path

# The file the seat writes in its own state before the cases, and must find
# unchanged after each.
RESTART_PROBE = "restart-probe"
# How long a started container may take to become healthy (the image's
# healthcheck reads sshd every 30 s, with a 10 s start period).
HEALTHY_WITHIN = 180


def digested(relative: str, seat: str) -> bool:
    """The files whose bytes a restart must keep: sshd's host keys, the
    seat's member key and certificates, and the probe."""
    parts = relative.split("/")
    if len(parts) == 2 and parts[0] == "ssh" and parts[1].startswith("ssh_host_"):
        return True
    seat_dir = ["seats", seat]
    if parts[:2] != seat_dir:
        return False
    rest = parts[2:]
    return rest in ([".aw", "signing.key"], [RESTART_PROBE]) or (len(rest) == 3 and rest[:2] == [".aw", "team-certs"])


def snapshot(root: Path, uid: int, gid: int, seat: str) -> dict:
    """Every entry of the state, never following a link: the entries whose
    owner is not the agents' uid and gid, every entry's mode, and the
    SHA-256 of the files a restart must keep (regular files only)."""
    def unreadable(error: OSError) -> None:
        raise Failed(f"{error.filename}: cannot be read ({error.strerror}); the snapshot is not whole")

    foreign, modes, digests = [], {}, {}
    for directory, dirs, files in os.walk(root, onerror=unreadable, followlinks=False):
        here = Path(directory)
        names = ["."] if here == root else []
        names += [str((here / name).relative_to(root)) for name in (*dirs, *files)]
        for relative in names:
            path = root if relative == "." else root / relative
            info = path.lstat()
            if (info.st_uid, info.st_gid) != (uid, gid):
                foreign.append(relative)
            modes[relative] = oct(stat.S_IMODE(info.st_mode))
            if stat.S_ISREG(info.st_mode) and digested(relative, seat):
                digests[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"foreign": sorted(foreign), "modes": modes, "digests": digests}


def state_drift(before: dict, after: dict) -> list[str]:
    """What changed between two snapshots that a restart must not change: a
    kept file gone, new or changed (a new key is a second onboarding), the
    mode of an entry present in both, and any entry not the agents' own.
    Entries the running agent adds or removes (logs, sockets) are not
    drift. Nothing to compare is drift too: an empty snapshot proves nothing."""
    if not before["digests"]:
        return ["no key, certificate or probe to compare"]
    drift = []
    for path in sorted(set(before["digests"]) | set(after["digests"])):
        if path not in after["digests"]:
            drift.append(f"{path}: gone")
        elif path not in before["digests"]:
            drift.append(f"{path}: new")
        elif before["digests"][path] != after["digests"][path]:
            drift.append(f"{path}: changed")
    for path in sorted(set(before["modes"]) & set(after["modes"])):
        if before["modes"][path] != after["modes"][path]:
            drift.append(f"{path}: mode {before['modes'][path]} -> {after['modes'][path]}")
    drift += [f"{path}: not the agents' owner" for path in after["foreign"]]
    return drift


def missing(taken: dict, seat: str, probe: str) -> list[str]:
    """What the bound state must hold before any case, so that the cases
    compare something: the probe the seat wrote over SSH, byte for byte (so
    SSH reached this very state), the seat's member key, a certificate, and
    sshd's private host key."""
    absent = []
    key = f"seats/{seat}/.aw/signing.key"
    if key not in taken["digests"]:
        absent.append(f"{key}: missing")
    if not [path for path in taken["digests"] if path.startswith(f"seats/{seat}/.aw/team-certs/")]:
        absent.append(f"seats/{seat}/.aw/team-certs/: no certificate")
    written = f"seats/{seat}/{RESTART_PROBE}"
    if written not in taken["digests"]:
        absent.append(f"{written}: missing")
    elif taken["digests"][written] != probe:
        absent.append(f"{written}: not the probe written over SSH")
    if not [path for path in taken["digests"] if path.startswith("ssh/ssh_host_") and not path.endswith(".pub")]:
        absent.append("ssh/: no private host key")
    return absent


def summary(taken: dict) -> dict:
    """A snapshot as evidence: counts and the kept files' names, no digest."""
    return {"entries": len(taken["modes"]), "kept": sorted(taken["digests"]), "foreign": taken["foreign"]}


class Failed(Exception):
    pass


# docker and docker compose ask the local daemon's socket alone, with no
# inherited context or configuration, so every observation and every change
# goes to one daemon.
DOCKER_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
              "DOCKER_HOST": "unix:///var/run/docker.sock"}


def run(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    env = DOCKER_ENV if args and args[0] == "docker" else None
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, check=False, env=env)


def required(result: subprocess.CompletedProcess, what: str) -> str:
    if result.returncode != 0:
        raise Failed(f"{what}: rc={result.returncode}: {(result.stdout + result.stderr).strip()[-500:]}")
    return result.stdout


class Agent:
    def __init__(self, args: argparse.Namespace):
        self.container = args.container
        self.state_dir = args.state_dir
        self.uid, self.gid = args.uid, args.gid
        self.seat = args.seat
        self.home = f"/state/seats/{args.seat}/.aw"
        self.ssh_config = args.ssh_config
        self.image_id = args.image_id
        self.compose = shlex.split(args.compose)
        self.peer = [args.peer_aw, "--identity-home", args.peer_home, "--json"]

    def inspect(self) -> dict:
        found = json.loads(required(run("docker", "inspect", self.container), f"docker inspect {self.container}"))
        if len(found) != 1:
            raise Failed(f"docker inspect {self.container}: {len(found)} containers")
        container = found[0]
        state = [mount["Source"] for mount in container["Mounts"] if mount["Destination"] == "/state"]
        return {"id": container["Id"], "image": container["Image"], "state_source": state,
                "health": container["State"].get("Health", {}).get("Status")}

    def healthy(self) -> dict:
        """The container as it stands once healthy, within HEALTHY_WITHIN
        seconds by the monotonic clock; its image and /state source checked."""
        deadline = time.monotonic() + HEALTHY_WITHIN
        while True:
            seen = self.inspect()
            if seen["health"] == "healthy":
                break
            if time.monotonic() > deadline:
                raise Failed(f"{self.container} not healthy within {HEALTHY_WITHIN}s: {seen['health']}")
            time.sleep(5)
        if seen["image"] != self.image_id:
            raise Failed(f"{self.container} runs image {seen['image']}, not {self.image_id}")
        if seen["state_source"] != [str(self.state_dir)]:
            raise Failed(f"{self.container} mounts /state from {seen['state_source']}, not {self.state_dir}")
        return seen

    def ssh(self, command: str) -> str:
        """A command as the agent over the operator's SSH; a host key other
        than the pinned one is refused by StrictHostKeyChecking."""
        return required(run("ssh", "-F", str(self.ssh_config), "team-agent", command), f"ssh: {command}")

    def did(self) -> str:
        answer = json.loads(self.ssh(f"aw --identity-home {self.home} --json whoami"))
        did = answer.get("did", "")
        if not did.startswith("did:key:"):
            raise Failed(f"the seat answered no did:key: {sorted(answer)}")
        return did

    def mail(self, seat_did: str, peer_did: str) -> dict:
        """A signed round trip after each transition: the peer, outside the
        container, sends; the seat finds that very message (by the send
        receipt's message_id) from the peer, verified; the seat replies,
        which it can only do with its own key; the peer finds that reply
        from the seat, verified."""
        if seat_did == peer_did:
            raise Failed(f"the seat and the peer are the same identity ({seat_did}); the round trip proves nothing")
        subject = f"acwd25-restart-{secrets.token_hex(6)}"
        sent = json.loads(required(run(*self.peer, "mail", "send", "--to", self.seat, "--subject", subject,
                                       "--body", "restart check", timeout=300), "the peer's mail"))
        sent_id = sent.get("message_id") or ""
        if not sent_id:
            raise Failed(f"the peer's send answered no message_id: {sorted(sent)}")
        inbox = json.loads(self.ssh(f"aw --identity-home {self.home} --json mail inbox --show-all"))
        found = [message for message in inbox.get("messages", []) if message.get("message_id") == sent_id]
        if len(found) != 1:
            raise Failed(f"the peer's mail {sent_id}: {len(found)} in the seat's inbox")
        received = found[0]
        if received.get("from_did") != peer_did or received.get("verification_status") != "verified":
            raise Failed(f"the peer's mail {sent_id}: from {received.get('from_did')},"
                         f" {received.get('verification_status')}; expected {peer_did}, verified")
        reply = json.loads(self.ssh(f"aw --identity-home {self.home} --json mail reply {sent_id} --body restart-reply"))
        reply_id = reply.get("message_id") or ""
        if not reply_id:
            raise Failed(f"the seat's reply answered no message_id: {sorted(reply)}")
        inbox = json.loads(required(run(*self.peer, "mail", "inbox", "--show-all", timeout=300), "the peer's inbox"))
        found = [message for message in inbox.get("messages", []) if message.get("message_id") == reply_id]
        if len(found) != 1:
            raise Failed(f"the seat's reply {reply_id}: {len(found)} in the peer's inbox")
        answered = found[0]
        if answered.get("from_did") != seat_did or answered.get("verification_status") != "verified":
            raise Failed(f"the seat's reply {reply_id}: from {answered.get('from_did')},"
                         f" {answered.get('verification_status')}; expected {seat_did}, verified")
        return {"sent": sent_id, "received_from": peer_did, "reply": reply_id, "reply_from": seat_did,
                "verification_status": "verified"}

    def peer_did(self) -> str:
        answer = json.loads(required(run(*self.peer, "whoami", timeout=120), "the peer's whoami"))
        did = answer.get("did", "")
        if not did.startswith("did:key:"):
            raise Failed(f"the peer answered no did:key: {sorted(answer)}")
        return did

    def write_probe(self) -> str:
        token = secrets.token_hex(16)
        self.ssh(f"umask 077 && printf %s {token} > /state/seats/{self.seat}/{RESTART_PROBE}")
        return hashlib.sha256(token.encode()).hexdigest()

    def snapshot(self) -> dict:
        return snapshot(self.state_dir, self.uid, self.gid, self.seat)


def check(agent: Agent, before: dict, container: dict, dids: dict) -> dict:
    """One case's after-checks against the record taken before the cases."""
    after = agent.snapshot()
    drift = state_drift(before, after)
    if drift:
        raise Failed("state drift: " + "; ".join(drift))
    answered = agent.did()
    if answered != dids["seat"]:
        raise Failed(f"the seat answers {answered}, not {dids['seat']}")
    return {"container": container, "did_key": answered, "state": summary(after), "drift": [],
            "mail": agent.mail(dids["seat"], dids["peer"])}


def restart(agent: Agent, before: dict, dids: dict, original: dict) -> dict:
    required(run("docker", "restart", "--time", "50", original["id"], timeout=120), "docker restart")
    seen = agent.healthy()
    if seen["id"] != original["id"]:
        raise Failed(f"docker restart gave another container: {seen['id']}")
    return check(agent, before, seen, dids)


def containers() -> list[dict]:
    """Every container this daemon lists, from a clean answer only."""
    answer = run("docker", "container", "ls", "--all", "--no-trunc", "--format", "{{json .}}")
    if answer.returncode != 0 or answer.stderr.strip():
        raise Failed(f"docker container ls failed (rc={answer.returncode}): {answer.stderr.strip()[-300:]}")
    listed = []
    for line in answer.stdout.splitlines():
        try:
            entry = json.loads(line)
            listed.append({"id": entry["ID"], "names": entry["Names"].split(",")})
        except (ValueError, KeyError, AttributeError):
            raise Failed(f"docker container ls answered an unreadable line: {line[:200]!r}") from None
    return listed


def remove_verified(agent: Agent, identity: str) -> None:
    """Removes the agent's container, and only it: the Compose project must
    name exactly one agent container, the one inspected (identity), before
    anything changes; that id, not the service, is stopped and removed; and
    its absence must be observed, not inferred from a failed look."""
    answer = run(*agent.compose, "ps", "--all", "--quiet", "agent")
    ids = answer.stdout.split()
    if answer.returncode != 0 or answer.stderr.strip() or len(ids) != 1:
        raise Failed(f"the Compose project's agent container is not known: rc={answer.returncode},"
                     f" {len(ids)} ids, {answer.stderr.strip()[-300:]!r}")
    if ids[0] != identity:
        raise Failed(f"the Compose project's agent {ids[0][:12]} is not the container inspected {identity[:12]}")
    required(run("docker", "stop", "--time", "50", identity, timeout=120), f"docker stop {identity[:12]}")
    required(run("docker", "rm", identity, timeout=120), f"docker rm {identity[:12]}")
    try:
        left = containers()
    except Failed as error:
        raise Failed(f"after docker rm, the container's absence is not known: {error}") from None
    if [entry for entry in left if entry["id"] == identity or agent.container in entry["names"]]:
        raise Failed(f"the agent's container still exists after docker rm {identity[:12]}")


def replace(agent: Agent, before: dict, dids: dict, original: dict) -> dict:
    remove_verified(agent, original["id"])
    required(run(*agent.compose, "up", "-d", "--no-deps", "agent", timeout=300), "compose up agent")
    seen = agent.healthy()
    if seen["id"] == original["id"]:
        raise Failed("compose up kept the removed container's id")
    return check(agent, before, seen, dids)


CASES = (("restart", restart), ("replace", replace))


def run_cases(agent, before: dict, dids: dict, original: dict, record, cases=CASES) -> dict:
    """Each case in order, each judged on its own. The container inspected
    before the cases is the one approved for removal, for the whole run: if
    another container holds the name after a case, the run stops there,
    recording the change, before anything is stopped or removed."""
    results = {name: "NOT RUN" for name, _ in cases}
    for index, (name, case) in enumerate(cases):
        if index:
            try:
                now = agent.inspect()
            except (Failed, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
                results[name] = f"FAILED: the container could not be inspected before {name}: {error}"
                record(name, {"failed": results[name]})
                break
            if now["id"] != original["id"]:
                results[name] = (f"FAILED: the container changed between the cases ({original['id'][:12]} became"
                                 f" {now['id'][:12]}); nothing was stopped or removed")
                record(name, {"failed": results[name], "approved": original["id"], "found": now["id"]})
                break
        try:
            record(name, case(agent, before, dids, original))
            results[name] = "PASS"
        except (Failed, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
            results[name] = f"FAILED: {error}"
            record(name, {"failed": str(error)})
            break
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--evidence", type=Path, required=True, help="a new directory for the evidence")
    parser.add_argument("--container", required=True)
    parser.add_argument("--state-dir", type=Path, required=True, help="the host directory bound at /state")
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--seat", required=True)
    parser.add_argument("--ssh-config", type=Path, required=True, help="defines Host team-agent, host key pinned")
    parser.add_argument("--image-id", required=True, help="the local image id the container must run")
    parser.add_argument("--compose", required=True, help="the Compose command that owns the agent service")
    parser.add_argument("--peer-aw", required=True, help="the aw binary the peer runs outside the container")
    parser.add_argument("--peer-home", required=True, help="the peer's identity home")
    args = parser.parse_args()
    if args.evidence.exists() or args.evidence.is_symlink():
        print(f"FAILED: {args.evidence} exists; each run has its own directory")
        return 2
    args.evidence.mkdir(mode=0o700, parents=True)

    def record(name: str, value: dict) -> None:
        (args.evidence / f"{name}.json").write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        print(name.upper() + ":", json.dumps(value, sort_keys=True))

    agent = Agent(args)
    try:
        original = agent.healthy()
        dids = {"seat": agent.did(), "peer": agent.peer_did()}
        if dids["seat"] == dids["peer"]:
            raise Failed(f"the seat and the peer are the same identity ({dids['seat']})")
        probe = agent.write_probe()
        before = agent.snapshot()
        if before["foreign"]:
            raise Failed("before the cases, entries not the agents' own: " + ", ".join(before["foreign"]))
        absent = missing(before, agent.seat, probe)
        if absent:
            raise Failed("before the cases, the bound state lacks: " + "; ".join(absent))
        record("before", {"container": original, "dids": dids, "probe_sha256": probe, "state": summary(before),
                          "mail": agent.mail(dids["seat"], dids["peer"])})
    except (Failed, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        record("result", {"before": f"FAILED: {error}", "restart": "NOT RUN", "replace": "NOT RUN"})
        return 1
    results = {"before": "PASS", **run_cases(agent, before, dids, original, record)}
    record("result", results)
    return 0 if all(value == "PASS" for value in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())

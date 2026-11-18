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

Before anything changes, it records the container, a probe file the seat
writes in its state, a snapshot of the state, and a verified mail from the
peer, an identity outside the container. Then two cases, each judged on
its own:

1. restart: docker restart of the same container (same id);
2. replace: only the agent's container is removed and created again by the
   given Compose command (a new id), with the same image and the same
   /state source.

After each: the container is healthy, SSH still accepts the pinned host
key, the seat answers with the same did:key, the snapshot shows no drift
(the same keys, certificate and probe, the same modes, every entry the
agents' own), and a fresh mail from the peer arrives verified. The probe and
the snapshot show no key or file content: digests of secrets stay in memory
and only their equality is written.

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
    foreign, modes, digests = [], {}, {}
    for directory, dirs, files in os.walk(root, followlinks=False):
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


def summary(taken: dict) -> dict:
    """A snapshot as evidence: counts and the kept files' names, no digest."""
    return {"entries": len(taken["modes"]), "kept": sorted(taken["digests"]), "foreign": taken["foreign"]}


class Failed(Exception):
    pass


def run(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, check=False)


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

    def mail(self) -> dict:
        """A fresh mail from the peer, found once in the seat's inbox with
        verification_status verified. The subject is new for each check, so
        no earlier mail can answer it."""
        subject = f"acwd25-restart-{secrets.token_hex(6)}"
        required(run(*self.peer, "mail", "send", "--to", self.seat, "--subject", subject, "--body", "restart check",
                     timeout=300), "the peer's mail")
        inbox = json.loads(self.ssh(f"aw --identity-home {self.home} --json mail inbox --show-all"))
        found = [message for message in inbox.get("messages", []) if message.get("subject") == subject]
        if len(found) != 1:
            raise Failed(f"the peer's mail {subject}: {len(found)} in the seat's inbox")
        status = found[0].get("verification_status")
        if status != "verified":
            raise Failed(f"the peer's mail {subject}: verification_status {status}")
        return {"subject": subject, "from": found[0].get("from_alias"), "verification_status": status}

    def write_probe(self) -> str:
        token = secrets.token_hex(16)
        self.ssh(f"umask 077 && printf %s {token} > /state/seats/{self.seat}/{RESTART_PROBE}")
        return hashlib.sha256(token.encode()).hexdigest()

    def snapshot(self) -> dict:
        return snapshot(self.state_dir, self.uid, self.gid, self.seat)


def check(agent: Agent, before: dict, container: dict, did: str) -> dict:
    """One case's after-checks against the record taken before the cases."""
    after = agent.snapshot()
    drift = state_drift(before, after)
    if drift:
        raise Failed("state drift: " + "; ".join(drift))
    answered = agent.did()
    if answered != did:
        raise Failed(f"the seat answers {answered}, not {did}")
    return {"container": container, "did_key": answered, "state": summary(after), "drift": [], "mail": agent.mail()}


def restart(agent: Agent, before: dict, did: str, original: dict) -> dict:
    required(run("docker", "restart", "--time", "50", agent.container, timeout=120), "docker restart")
    seen = agent.healthy()
    if seen["id"] != original["id"]:
        raise Failed(f"docker restart gave another container: {seen['id']}")
    return check(agent, before, seen, did)


def replace(agent: Agent, before: dict, did: str, original: dict) -> dict:
    required(run(*agent.compose, "rm", "--stop", "--force", "agent", timeout=120), "compose rm agent")
    if run("docker", "inspect", original["id"]).returncode == 0:
        raise Failed(f"the agent's container {original['id']} still exists after compose rm")
    required(run(*agent.compose, "up", "-d", "--no-deps", "agent", timeout=300), "compose up agent")
    seen = agent.healthy()
    if seen["id"] == original["id"]:
        raise Failed("compose up kept the removed container's id")
    return check(agent, before, seen, did)


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
    results: dict[str, str] = {}
    try:
        original = agent.healthy()
        did = agent.did()
        probe = agent.write_probe()
        before = agent.snapshot()
        if before["foreign"]:
            raise Failed("before the cases, entries not the agents' own: " + ", ".join(before["foreign"]))
        if state_drift(before, before):
            raise Failed("before the cases: " + "; ".join(state_drift(before, before)))
        record("before", {"container": original, "did_key": did, "probe_sha256": probe, "state": summary(before),
                          "mail": agent.mail()})
    except (Failed, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        record("result", {"before": f"FAILED: {error}", "restart": "NOT RUN", "replace": "NOT RUN"})
        return 1
    for name, case in (("restart", restart), ("replace", replace)):
        try:
            record(name, case(agent, before, did, original))
            results[name] = "PASS"
            original = agent.inspect()
        except (Failed, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
            results[name] = f"FAILED: {error}"
            record(name, {"failed": str(error)})
            break
    results = {"before": "PASS", "restart": results.get("restart", "NOT RUN"), "replace": results.get("replace", "NOT RUN")}
    record("result", results)
    return 0 if all(value == "PASS" for value in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())

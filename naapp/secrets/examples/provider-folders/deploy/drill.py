"""The replay drill: the pinned replay.py, run as its runner job runs it,
against the Graph stand-in over real TLS.

    uv run python -I deploy/drill.py --root ROOT --python PYTHON [--pinned]

ROOT is an install tree (deploy/vendor.py assemble); PYTHON the interpreter
the job pins. Each replay is `PYTHON -I -B ROOT/replay.py --config FILE`
from an empty environment, with a dummy token file. With --pinned, the tree
must be exactly the vendor-lock.json pin before and after.

Cases: the trust root (the lab CA from ca_bundle only, never from the
environment), a cutover with a queued export carried to a fresh publisher
state, a lost answer after commit reconciled from restored state, the
whole ledger removed, and the output bound (exit 6 read through its
counts). Every case reads the folder back: each job is exactly one item
with its bytes and binding. This qualifies the publisher's handling only,
not Graph access, scope or account support.

One JSON receipt on stdout; exit 0 when every case passed, 1 otherwise.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import argparse  # noqa: E402

from deploy.standin_tls import TLSStandIn, lab_ca  # noqa: E402
from deploy.vendor import LOCK, PACKAGE, expected_files, installed_files  # noqa: E402
from publisher import format_binding  # noqa: E402
from submit import submit  # noqa: E402
from tests.outbox import provision_outbox  # noqa: E402
from tests.standin import TOKEN  # noqa: E402

SEAT = "drill-seat"
REPLAY_TIMEOUT_S = 120


@dataclass
class Case:
    name: str
    checks: list[tuple[str, bool]] = field(default_factory=list)

    def check(self, what: str, holds: bool) -> None:
        self.checks.append((what, bool(holds)))

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(holds for _, holds in self.checks)

    def record(self) -> dict:
        return {
            "case": self.name,
            "passed": self.passed,
            "failed": [what for what, holds in self.checks if not holds],
        }


class Drill:
    def __init__(self, root: Path, python: str, work: Path, served: TLSStandIn):
        self.root, self.python, self.work, self.served = root, python, work, served
        self.outbox = work / "outbox"
        self.outbox.mkdir()
        provision_outbox(self.outbox)
        self.token = work / "token"
        self.token.write_text(TOKEN + "\n")
        self.jobs: dict[str, tuple[str, bytes]] = {}

    def config(self, state: Path, ca_bundle: Path | None, output_max_bytes: int = 65536) -> Path:
        approot = self.served.standin.approot
        body = {
            "seat": SEAT,
            "state_dir": str(state),
            "outbox": str(self.outbox),
            "max_bytes": 1024 * 1024,
            "extensions": ["md"],
            "destination": {
                "drive_id": approot["parentReference"]["driveId"],
                "folder_id": approot["id"],
            },
            "graph_origin": self.served.graph_origin,
            "token_file": str(self.token),
            "ca_bundle": None if ca_bundle is None else str(ca_bundle),
            "output_max_bytes": output_max_bytes,
        }
        path = self.work / f"config-{uuid.uuid4().hex}.json"
        path.write_text(json.dumps(body))
        return path

    def replay(self, config: Path, env: dict[str, str] | None = None) -> tuple[int, dict]:
        done = subprocess.run(
            [self.python, "-I", "-B", str(self.root / "replay.py"), "--config", str(config)],
            env=env or {},
            cwd=self.work,
            capture_output=True,
            timeout=REPLAY_TIMEOUT_S,
        )
        if done.stderr:
            return done.returncode, {"stderr": done.stderr.decode(errors="replace")}
        return done.returncode, json.loads(done.stdout)

    def queue(self, content: bytes, target: str) -> str:
        job_id = str(uuid.uuid4())
        submit(self.outbox, job_id=job_id, content=content, extension="md", target=target)
        self.jobs[job_id] = (target, content)
        return job_id

    def read_back(self, case: Case) -> None:
        """Every queued job is exactly one item, with its bytes and binding."""
        items = list(self.served.standin.items.values())
        for job_id, (target, content) in self.jobs.items():
            named = [item for item in items if item["name"] == target]
            binding = format_binding(SEAT, job_id, _sha256(content))
            case.check(
                f"{target}: exactly one item with its bytes and binding",
                len(named) == 1
                and named[0]["content"] == content
                and named[0].get("description") == binding,
            )
        case.check("no item beyond the queued jobs", len(items) == len(self.jobs))

    def bearer_requests(self, since: int) -> int:
        return sum("Authorization" in r.headers for r in self.served.requests[since:])


def outcomes(body: dict) -> dict[str, str]:
    return {receipt["job_id"]: receipt["outcome"] for receipt in body.get("receipts", [])}


def trust_root(drill: Drill, lab) -> Case:
    case = Case("trust root: the lab CA only through ca_bundle")
    state = drill.work / "state-trust"
    for env, label in (
        ({}, "no ca_bundle"),
        (
            {"SSL_CERT_FILE": str(lab.ca_pem), "SSL_CERT_DIR": str(lab.directory)},
            "no ca_bundle, CA named by environment",
        ),
    ):
        since = len(drill.served.requests)
        code, body = drill.replay(drill.config(state, None), env)
        case.check(
            f"{label}: exit 5 provider_unavailable",
            (code, body.get("reason")) == (5, "provider_unavailable"),
        )
        case.check(f"{label}: no request carried the bearer", drill.bearer_requests(since) == 0)
    since = len(drill.served.requests)
    code, body = drill.replay(
        drill.config(state, lab.ca_pem),
        {"HTTPS_PROXY": "http://127.0.0.1:9", "ALL_PROXY": "http://127.0.0.1:9"},
    )
    case.check(
        "ca_bundle with a proxy in the environment: exit 0, the proxy ignored",
        (code, body.get("outcome")) == (0, "ok"),
    )
    case.check(
        "the bearer reached only the Graph origin",
        all(
            ("Authorization" in r.headers)
            == (f"https://{r.url.netloc.decode()}" == drill.served.graph_origin)
            for r in drill.served.requests[since:]
        ),
    )
    shutil.rmtree(state, ignore_errors=True)
    return case


def cutover(drill: Drill, lab) -> Case:
    case = Case("cutover: a queued export carried to a fresh publisher state")
    old, new = drill.work / "state-old", drill.work / "state-new"
    published = drill.queue(b"# Published before cutover\n", "before.md")
    code, body = drill.replay(drill.config(old, lab.ca_pem))
    case.check(
        "old publisher: exit 0, published", (code, outcomes(body)) == (0, {published: "published"})
    )
    queued = drill.queue(b"# Queued at cutover\n", "queued.md")
    commits = drill.served.standin.committed_uploads
    code, body = drill.replay(drill.config(new, lab.ca_pem))
    case.check(
        "new publisher, outbox carried: the published one already_published, the queued one published",
        (code, outcomes(body)) == (0, {published: "already_published", queued: "published"}),
    )
    case.check("exactly one new upload", drill.served.standin.committed_uploads == commits + 1)
    drill.read_back(case)
    return case


def lost_answer(drill: Drill, lab) -> Case:
    case = Case("lost answer: remote committed, no local receipt")
    state = drill.work / "state-new"
    backup = drill.work / "state-backup"
    shutil.copytree(state, backup)
    job = drill.queue(b"# Answer lost after commit\n", "lost.md")
    drill.served.standin.lose_next_commit_response = True
    commits = drill.served.standin.committed_uploads
    code, body = drill.replay(drill.config(state, lab.ca_pem))
    case.check(
        "the lost answer: exit 4, uncertain", (code, outcomes(body).get(job)) == (4, "uncertain")
    )
    case.check("the item was committed once", drill.served.standin.committed_uploads == commits + 1)
    shutil.rmtree(state)
    shutil.copytree(backup, state)
    code, body = drill.replay(drill.config(state, lab.ca_pem))
    case.check(
        "restored state without its receipt: exit 0, already_published",
        (code, outcomes(body).get(job)) == (0, "already_published"),
    )
    case.check("no second upload", drill.served.standin.committed_uploads == commits + 1)
    drill.read_back(case)
    return case


def ledger_removed(drill: Drill, lab) -> Case:
    case = Case("whole ledger removed")
    state = drill.work / "state-new"
    shutil.rmtree(state)
    commits = drill.served.standin.committed_uploads
    code, body = drill.replay(drill.config(state, lab.ca_pem))
    case.check(
        "exit 0, every job already_published",
        code == 0
        and set(outcomes(body)) == set(drill.jobs)
        and set(outcomes(body).values()) == {"already_published"},
    )
    case.check("no upload", drill.served.standin.committed_uploads == commits)
    drill.read_back(case)
    return case


def output_bound(drill: Drill, lab) -> Case:
    case = Case("output bound: exit 6 is read through its counts")
    code, body = drill.replay(
        drill.config(drill.work / "state-new", lab.ca_pem, output_max_bytes=512)
    )
    case.check("exit 6 output_too_large", (code, body.get("outcome")) == (6, "output_too_large"))
    case.check(
        "the counts say every job already_published and nothing uncertain",
        body.get("counts") == {"already_published": len(drill.jobs)},
    )
    return case


CASES = (trust_root, cutover, lost_answer, ledger_removed, output_bound)


def run(root: Path, python: str, pinned: bool) -> dict:
    version = subprocess.run(
        [python, "-I", "-c", "import sys; print('.'.join(map(str, sys.version_info[:3])))"],
        env={},
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout.strip()
    tree_before = installed_files(root)
    records = []
    if pinned:
        expected = expected_files(
            json.loads(LOCK.read_bytes()), PACKAGE, tuple(map(int, version.split(".")))
        )
        records.append({"case": "tree is the pin", "passed": tree_before == expected, "failed": []})
    with tempfile.TemporaryDirectory(prefix="provider-folders-drill-") as scratch:
        work = Path(scratch)
        lab = lab_ca(work / "lab-ca")
        with TLSStandIn(lab) as served:
            drill = Drill(root, python, work, served)
            for case in CASES:
                records.append(case(drill, lab).record())
    unchanged = installed_files(root) == tree_before
    records.append({"case": "tree unchanged by the replays", "passed": unchanged, "failed": []})
    return {
        "v": 1,
        "drill": "provider-folders replay over TLS",
        "python": version,
        "tree_files": len(tree_before),
        "cases": records,
        "result": "PASS" if all(record["passed"] for record in records) else "FAIL",
    }


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="drill.py")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--python", required=True)
    parser.add_argument("--pinned", action="store_true")
    arguments = parser.parse_args(argv)
    receipt = run(arguments.root, arguments.python, arguments.pinned)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

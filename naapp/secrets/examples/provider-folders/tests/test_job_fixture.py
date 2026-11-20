"""The publisher's job/1 FIXTURE stays consistent with what it pins.

deploy/runner-config.fixture.json is a labelled fixture: its executable pin, runner
ID, agent UID, credential reference and destination are stand-in values
(deploy/job-facts.json says whose each real value is). What is not a stand-in
is checked here: the declared files are exactly the pinned tree and the
operator config, the config is one replay.py accepts, the argv is how the
runner job runs replay.py, and the environment is exactly the declared
credential field, with no variable that changes TLS trust. The Secrets
runner's own parser and digest check the definition; its receipt is the
fixture's, not an owner-approved digest.
"""

import hashlib
import json
import subprocess
import sys
import uuid

import httpx
from aweb_secrets_values.credential_shapes import has_credential_shape

from deploy.vendor import LOCK, PACKAGE, expected_files
from replay import TOKEN_ENV, ExitCode, load_config, run
from submit import submit
from tests.outbox import provision_outbox
from tests.standin import TOKEN, OneDriveStandIn

DEPLOY = PACKAGE / "deploy"
INSTALL = "/opt/acwd25/publisher"
CONFIG = "/etc/acwd25/publisher.json"
JOB_ID = "acwd25-publisher"
# OpenSSL reads these from the environment before replay.py can act; the
# job's environment must never set them.
TLS_ENVIRONMENT = {"SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"}

config = json.loads((DEPLOY / "runner-config.fixture.json").read_bytes())
pin = config["jobs"][JOB_ID]
job = pin["definition"]
facts = {
    name: field["fixture"]
    for name, field in json.loads((DEPLOY / "job-facts.json").read_bytes())["fields"].items()
}


def test_the_declared_files_are_the_pinned_tree_and_the_operator_config():
    python = tuple(int(part) for part in facts["python_version"].split("."))
    expected = {
        f"{INSTALL}/{path}": digest
        for path, digest in expected_files(json.loads(LOCK.read_bytes()), PACKAGE, python).items()
    }
    expected[CONFIG] = hashlib.sha256((DEPLOY / "publisher.json").read_bytes()).hexdigest()
    declared = {item["path"]: item["sha256"] for item in job["exec"]["files"]}
    assert declared == expected
    assert [item["path"] for item in job["exec"]["files"]] == sorted(expected)


def test_the_operator_config_is_one_replay_accepts(tmp_path):
    copy = tmp_path / "publisher.json"
    copy.write_bytes((DEPLOY / "publisher.json").read_bytes())
    loaded = load_config(copy)
    # The runner's bound covers stdout and stderr together: replay's report
    # plus the one newline main writes after it.
    assert job["output"]["max_bytes"] == loaded.output_max_bytes + 1
    destination = facts["destination"]
    assert (loaded.destination.drive_id, loaded.destination.folder_id) == (
        destination["drive_id"],
        destination["folder_id"],
    )
    paths = facts["seat_and_paths"]
    assert (loaded.seat, str(loaded.outbox), str(loaded.state_dir)) == (
        paths["seat"],
        paths["outbox"],
        paths["state_dir"],
    )


def test_the_job_runs_replay_as_the_runner_does():
    assert job["kind"] == "exec" and job["oci"] is None
    assert (job["exec"]["path"], job["exec"]["sha256"]) == (
        facts["python_path"],
        facts["python_sha256"],
    )
    assert job["argv"] == ["-I", "-B", f"{INSTALL}/replay.py", "--config", CONFIG]
    assert (job["params"], job["runner_ids"]) == ({}, [facts["runner_id"]])
    assert config["agent_uids"] == [facts["agent_uid"]]


def test_the_environment_is_exactly_the_declared_credential_field():
    [slot] = job["credentials"]
    assert slot == {"secret_ref": facts["secret_ref"], "delivery": "durable", "mint": None}
    assert job["allow_durable"] is True
    assert job["env"] == {TOKEN_ENV: {"$credential": facts["secret_ref"], "field": "value"}}


def test_no_variable_that_changes_tls_trust_is_declared():
    names = set(job["env"])
    assert not names & TLS_ENVIRONMENT
    assert not any(name.upper().startswith("OPENSSL_") for name in names)


def replay_reports(tmp_path) -> dict[str, bytes]:
    """Replay's own report for each shape it has, as main writes it (one
    line), from runs against the stand-in: published and refused receipts,
    receipts already published, a whole run refused, and the counts-only
    body of exit 6."""
    standin = OneDriveStandIn()
    outbox = tmp_path / "outbox"
    outbox.mkdir()
    provision_outbox(outbox)
    for index in range(3):
        content = f"# Report {index}\n".encode()
        submit(
            outbox,
            job_id=str(uuid.uuid4()),
            content=content,
            extension="md",
            target=f"report-{index}.md",
        )
    # The same content again from a fresh job: refused as a duplicate.
    submit(
        outbox,
        job_id=str(uuid.uuid4()),
        content=b"# Report 0\n",
        extension="md",
        target="report-0.md",
    )

    def configured(output_max_bytes: int):
        approot = standin.approot
        body = {
            **json.loads((DEPLOY / "publisher.json").read_bytes()),
            "state_dir": str(tmp_path / "state"),
            "outbox": str(outbox),
            "graph_origin": "https://graph.standin.invalid",
            "output_max_bytes": output_max_bytes,
            "destination": {
                "drive_id": approot["parentReference"]["driveId"],
                "folder_id": approot["id"],
            },
        }
        path = tmp_path / f"publisher-{output_max_bytes}.json"
        path.write_text(json.dumps(body))
        return load_config(path)

    shapes = (
        ("published and refused", 65536, TOKEN, ExitCode.REFUSED),
        ("already published", 65536, TOKEN, ExitCode.REFUSED),
        ("run refused", 65536, None, ExitCode.RUN_REFUSED),
        ("output too large", 512, TOKEN, ExitCode.OUTPUT_TOO_LARGE),
    )
    reports = {}
    with httpx.Client(transport=standin.transport()) as client:
        for name, output_max_bytes, token, expected in shapes:
            code, output = run(configured(output_max_bytes), client, token)
            assert code is expected, name
            reports[name] = output + b"\n"
    return reports


def test_no_replay_report_is_withheld_by_the_runner_classifier(tmp_path):
    """The runner withholds a job's whole output when has_credential_shape
    fires on it (runner execution _report). Replay's reports must not, in
    each shape and with Graph's documented business and personal item id
    forms in place of the stand-in's."""
    reports = replay_reports(tmp_path)
    published = json.loads(reports["published and refused"])
    assert {receipt["outcome"] for receipt in published["receipts"]} == {"published", "refused"}
    for item_id in ("01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K", "D4648F06C91D9D3D!54927"):
        receipts = [{**r, "item_id": item_id} if r["item_id"] else r for r in published["receipts"]]
        body = {**published, "receipts": receipts}
        reports[f"published, item id {item_id}"] = json.dumps(body, sort_keys=True).encode() + b"\n"
    for name, report in reports.items():
        assert not has_credential_shape(report), name
    # The classifier is live on this shape: a bearer-shaped value in a
    # report field is withheld.
    leaked = {
        **published,
        "reason": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkcmlsbCJ9.c2lnbmF0dXJlLW5vdC1yZWFs",
    }
    assert has_credential_shape(json.dumps(leaked, sort_keys=True).encode())


def test_replay_writes_nothing_to_stderr_on_a_completed_run(tmp_path):
    """A run that completes, here refused before any job because no
    credential arrived, writes one line to stdout within the bound and
    nothing to stderr: only argparse's usage error (exit 2) or a crash
    (exit 1) writes there."""
    copy = tmp_path / "publisher.json"
    copy.write_bytes((DEPLOY / "publisher.json").read_bytes())
    done = subprocess.run(
        [sys.executable, "-I", "-B", str(PACKAGE / "replay.py"), "--config", str(copy)],
        env={},
        capture_output=True,
        timeout=60,
    )
    assert (done.returncode, done.stderr) == (ExitCode.RUN_REFUSED, b"")
    assert done.stdout.count(b"\n") == 1 and len(done.stdout) <= job["output"]["max_bytes"]
    assert json.loads(done.stdout)["reason"] == "token_unavailable"

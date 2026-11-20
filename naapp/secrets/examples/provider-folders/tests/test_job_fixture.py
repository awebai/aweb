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

from deploy.vendor import LOCK, PACKAGE, expected_files
from replay import TOKEN_ENV, load_config

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
    assert job["output"]["max_bytes"] > loaded.output_max_bytes
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

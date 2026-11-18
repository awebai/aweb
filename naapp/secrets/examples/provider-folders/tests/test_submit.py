"""The agent's submit helper leaves only files the publisher's group can read."""

import hashlib
import json
import os
import stat
import uuid

import pytest

from submit import SubmitRefused, submit
from tests.outbox import provision_outbox

REPORT = b"# Synthetic brief answer\n"


@pytest.fixture
def outbox(tmp_path):
    path = tmp_path / "outbox"
    path.mkdir()
    provision_outbox(path)
    return path


def test_submit_writes_a_group_readable_report_then_its_manifest(outbox):
    job_id = str(uuid.uuid4())

    submit(outbox, job_id=job_id, content=REPORT, extension="md", target="answer.md")

    report = outbox / f"{job_id}.md"
    manifest = outbox / f"{job_id}.json"
    for path in (report, manifest):
        info = path.stat()
        assert stat.S_IMODE(info.st_mode) == 0o640
        assert info.st_gid == outbox.stat().st_gid
    assert json.loads(manifest.read_text()) == {
        "job_id": job_id,
        "file": f"{job_id}.md",
        "size": len(REPORT),
        "sha256": hashlib.sha256(REPORT).hexdigest(),
        "target": "answer.md",
    }
    assert sorted(p.name for p in outbox.iterdir()) == sorted([report.name, manifest.name])


def test_submit_sets_modes_despite_a_restrictive_umask(outbox):
    previous = os.umask(0o077)
    try:
        job_id = str(uuid.uuid4())
        submit(outbox, job_id=job_id, content=REPORT, extension="md", target="answer.md")
    finally:
        os.umask(previous)

    assert stat.S_IMODE((outbox / f"{job_id}.md").stat().st_mode) == 0o640


@pytest.mark.parametrize("mode", [0o0750, 0o2700, 0o2710, 0o2740])
def test_submit_refuses_an_outbox_the_publisher_group_cannot_read(outbox, mode):
    os.chmod(outbox, mode)
    job_id = str(uuid.uuid4())

    with pytest.raises(SubmitRefused):
        submit(outbox, job_id=job_id, content=REPORT, extension="md", target="answer.md")

    assert not (outbox / f"{job_id}.json").exists()


def test_submit_refuses_an_outbox_of_another_group(outbox):
    job_id = str(uuid.uuid4())

    with pytest.raises(SubmitRefused):
        submit(
            outbox,
            job_id=job_id,
            content=REPORT,
            extension="md",
            target="answer.md",
            expected_gid=outbox.stat().st_gid + 1,
        )

    assert not (outbox / f"{job_id}.json").exists()


def test_submit_never_replaces_an_existing_manifest(outbox):
    job_id = str(uuid.uuid4())
    submit(outbox, job_id=job_id, content=REPORT, extension="md", target="answer.md")

    with pytest.raises(SubmitRefused):
        submit(outbox, job_id=job_id, content=REPORT + b"x", extension="md", target="answer.md")

    assert (outbox / f"{job_id}.md").read_bytes() == REPORT

"""Publisher handling against the local OneDrive stand-in.

These tests exercise refusal, idempotency and recovery. They do not qualify
real provider access, scope or account support.
"""

import hashlib
import json
import os
import uuid

import httpx
import pytest

from onedrive import GraphAppFolder
from publisher import (
    DirectoryOutbox,
    PublishConfig,
    Publisher,
    PublishUncertain,
    Refused,
    format_binding,
)
from submit import submit
from tests.outbox import provision_outbox
from tests.standin import GRAPH, TOKEN, OneDriveStandIn

SEAT = "fictional-seat"
REPORT = b"# Quarterly summary for Fictional Ltd\n\nAll figures are synthetic.\n"


@pytest.fixture
def standin():
    return OneDriveStandIn()


@pytest.fixture
def outbox_dir(tmp_path):
    path = tmp_path / "outbox"
    path.mkdir()
    provision_outbox(path)
    return path


@pytest.fixture
def state_dir(tmp_path):
    return tmp_path / "publisher-state"


def make_publisher(standin, outbox_dir, state_dir, **overrides):
    config = PublishConfig(
        seat=SEAT,
        state_dir=state_dir,
        max_bytes=overrides.pop("max_bytes", 20 * 1024 * 1024),
        extensions=frozenset({"pdf", "docx", "md", "txt"}),
    )
    client = httpx.Client(transport=standin.transport())
    folder = GraphAppFolder(client, token=lambda: TOKEN, base=GRAPH)
    return Publisher(config, DirectoryOutbox(outbox_dir), folder)


def new_job(outbox_dir, content=REPORT, target="summary.md", job_id=None):
    job_id = job_id or str(uuid.uuid4())
    submit(outbox_dir, job_id=job_id, content=content, extension="md", target=target)
    return job_id


def resubmit(outbox_dir, job_id, content=REPORT, target="summary.md"):
    """An agent withdrawing a queued job and submitting it again under the same job_id."""
    (outbox_dir / f"{job_id}.json").unlink()
    return new_job(outbox_dir, content=content, target=target, job_id=job_id)


def rewrite_manifest(outbox_dir, job, **fields):
    path = outbox_dir / f"{job}.json"
    manifest = json.loads(path.read_text())
    manifest.update(fields)
    path.write_text(json.dumps(manifest))


def test_publishes_once_with_the_binding_on_the_item_and_reads_back(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    publisher = make_publisher(standin, outbox_dir, state_dir)

    receipt = publisher.publish(job_id)

    assert receipt.outcome == "published"
    assert receipt.sha256 == hashlib.sha256(REPORT).hexdigest()
    [item] = standin.items.values()
    assert item["id"] == receipt.item_id
    assert item["name"] == "summary.md"
    assert item["description"] == format_binding(SEAT, job_id, receipt.sha256)
    assert publisher.folder.download(receipt.item_id) == REPORT
    stored = json.loads((state_dir / "receipts" / f"{job_id}.json").read_text())
    assert stored["outcome"] == "published"
    assert stored["item_id"] == receipt.item_id


def test_resubmitting_the_same_job_writes_nothing(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    publisher = make_publisher(standin, outbox_dir, state_dir)
    first = publisher.publish(job_id)

    again = publisher.publish(job_id)

    assert again.outcome == "already_published"
    assert again.item_id == first.item_id
    assert standin.committed_uploads == 1
    assert len(standin.items) == 1


def test_same_job_with_different_content_is_a_conflict(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    publisher = make_publisher(standin, outbox_dir, state_dir)
    publisher.publish(job_id)
    before = standin.snapshot()

    resubmit(outbox_dir, job_id, content=REPORT + b"changed\n")
    receipt = publisher.publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "job_conflict")
    assert standin.snapshot() == before


def test_same_job_with_a_different_target_is_a_conflict(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    publisher = make_publisher(standin, outbox_dir, state_dir)
    publisher.publish(job_id)
    before = standin.snapshot()

    resubmit(outbox_dir, job_id, target="elsewhere.md")
    receipt = publisher.publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "job_conflict")
    assert standin.snapshot() == before


def test_a_new_job_with_the_same_content_and_target_is_a_duplicate(standin, outbox_dir, state_dir):
    publisher = make_publisher(standin, outbox_dir, state_dir)
    publisher.publish(new_job(outbox_dir))
    before = standin.snapshot()

    receipt = publisher.publish(new_job(outbox_dir))

    assert (receipt.outcome, receipt.reason) == ("refused", "duplicate")
    assert standin.snapshot() == before


def test_a_target_taken_by_other_content_is_refused_untouched(standin, outbox_dir, state_dir):
    standin.add_item("summary.md", b"someone else's file\n")
    before = standin.snapshot()
    publisher = make_publisher(standin, outbox_dir, state_dir)

    receipt = publisher.publish(new_job(outbox_dir))

    assert (receipt.outcome, receipt.reason) == ("refused", "target_taken")
    assert standin.snapshot() == before


def test_a_target_created_concurrently_is_refused_not_overwritten(standin, outbox_dir, state_dir):
    standin.insert_before_next_commit = ("summary.md", b"raced in first\n")
    publisher = make_publisher(standin, outbox_dir, state_dir)

    receipt = publisher.publish(new_job(outbox_dir))

    assert (receipt.outcome, receipt.reason) == ("refused", "target_taken")
    [item] = standin.items.values()
    assert item["content"] == b"raced in first\n"
    assert standin.committed_uploads == 0


def test_a_lost_response_after_the_write_reconciles_to_one_item(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    publisher = make_publisher(standin, outbox_dir, state_dir)
    standin.lose_next_commit_response = True

    with pytest.raises(PublishUncertain):
        publisher.publish(job_id)
    receipt = publisher.publish(job_id)

    assert receipt.outcome == "already_published"
    assert standin.committed_uploads == 1
    assert len(standin.items) == 1


def test_a_lost_response_and_a_lost_ledger_still_reconcile_to_one_item(
    standin, outbox_dir, state_dir
):
    job_id = new_job(outbox_dir)
    publisher = make_publisher(standin, outbox_dir, state_dir)
    standin.lose_next_commit_response = True
    with pytest.raises(PublishUncertain):
        publisher.publish(job_id)

    (state_dir / "ledger.json").unlink()
    receipt = make_publisher(standin, outbox_dir, state_dir).publish(job_id)

    assert receipt.outcome == "already_published"
    assert standin.committed_uploads == 1
    assert len(standin.items) == 1


def test_replaying_the_outbox_without_a_ledger_writes_nothing(standin, outbox_dir, state_dir):
    publisher = make_publisher(standin, outbox_dir, state_dir)
    jobs = [
        new_job(outbox_dir, content=REPORT + bytes([n]), target=f"summary-{n}.md") for n in range(3)
    ]
    for job_id in jobs:
        publisher.publish(job_id)
    before = standin.snapshot()

    (state_dir / "ledger.json").unlink()
    receipts = make_publisher(standin, outbox_dir, state_dir).replay()

    assert sorted(r.job_id for r in receipts) == sorted(jobs)
    assert {r.outcome for r in receipts} == {"already_published"}
    assert standin.snapshot() == before
    assert standin.committed_uploads == 3


def test_a_ledger_from_another_destination_is_refused(standin, outbox_dir, state_dir):
    publisher = make_publisher(standin, outbox_dir, state_dir)
    publisher.publish(new_job(outbox_dir))

    standin.approot = {**standin.approot, "id": "OTHER-APPROOT"}
    with pytest.raises(Refused, match="destination_changed"):
        make_publisher(standin, outbox_dir, state_dir).publish(new_job(outbox_dir))


def test_the_binding_is_persisted_before_the_provider_write(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    publisher = make_publisher(standin, outbox_dir, state_dir)
    seen = []
    standin.before_commit = lambda: seen.append(json.loads((state_dir / "ledger.json").read_text()))

    publisher.publish(job_id)

    [ledger] = seen
    entry = ledger["jobs"][job_id]
    assert entry["seat"] == SEAT
    assert entry["sha256"] == hashlib.sha256(REPORT).hexdigest()
    assert entry["target"] == "summary.md"
    assert entry["status"] == "pending"
    assert ledger["destination"] == {"drive_id": "standin-drive", "folder_id": "STANDIN-APPROOT"}


def test_an_uncertain_write_is_recorded_as_uncertain(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    publisher = make_publisher(standin, outbox_dir, state_dir)
    standin.lose_next_commit_response = True

    with pytest.raises(PublishUncertain):
        publisher.publish(job_id)

    ledger = json.loads((state_dir / "ledger.json").read_text())
    assert ledger["jobs"][job_id]["status"] == "uncertain"


def test_items_bound_to_another_seat_are_not_this_jobs(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    sha = hashlib.sha256(REPORT).hexdigest()
    standin.add_item("summary.md", REPORT, format_binding("another-seat", job_id, sha))
    before = standin.snapshot()

    receipt = make_publisher(standin, outbox_dir, state_dir).publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "target_taken")
    assert standin.snapshot() == before


def test_a_remote_item_whose_content_does_not_match_its_binding_is_a_conflict(
    standin, outbox_dir, state_dir
):
    job_id = new_job(outbox_dir)
    sha = hashlib.sha256(REPORT).hexdigest()
    tampered = REPORT.replace(b"synthetic", b"invented!")
    assert len(tampered) == len(REPORT)
    standin.add_item("summary.md", tampered, format_binding(SEAT, job_id, sha))
    before = standin.snapshot()

    receipt = make_publisher(standin, outbox_dir, state_dir).publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "job_conflict")
    assert standin.snapshot() == before


def test_listing_follows_pages(standin, outbox_dir, state_dir):
    for n in range(5):
        standin.add_item(f"other-{n}.txt", bytes([n]))
    job_id = new_job(outbox_dir, target="zz-last.md")
    publisher = make_publisher(standin, outbox_dir, state_dir)
    publisher.publish(job_id)

    (state_dir / "ledger.json").unlink()
    receipt = make_publisher(standin, outbox_dir, state_dir).publish(job_id)

    assert receipt.outcome == "already_published"
    assert standin.committed_uploads == 1


def test_a_next_link_to_another_origin_is_refused_without_sending_the_token(
    standin, outbox_dir, state_dir
):
    for n in range(3):
        standin.add_item(f"other-{n}.txt", bytes([n]))
    standin.foreign_next_link = "https://elsewhere.invalid/children?skiptoken=2"
    publisher = make_publisher(standin, outbox_dir, state_dir)

    with pytest.raises(PublishUncertain, match="next_link_origin"):
        publisher.publish(new_job(outbox_dir))
    assert standin.committed_uploads == 0


def test_a_provider_denial_is_refused(standin, outbox_dir, state_dir):
    standin.deny_all = True

    receipt = make_publisher(standin, outbox_dir, state_dir).publish(new_job(outbox_dir))

    assert (receipt.outcome, receipt.reason) == ("refused", "provider_denied")
    assert standin.items == {}


# Untrusted manifest and report.


def test_a_report_over_the_bound_is_refused_while_reading(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir, content=b"x" * 2048)
    publisher = make_publisher(standin, outbox_dir, state_dir, max_bytes=1024)

    receipt = publisher.publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "too_large")
    assert standin.items == {}


def test_a_report_larger_than_its_manifest_size_is_refused(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    (outbox_dir / f"{job_id}.md").write_bytes(REPORT + b"appended later\n")

    receipt = make_publisher(standin, outbox_dir, state_dir).publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "size_mismatch")
    assert standin.items == {}


def test_a_report_whose_bytes_do_not_match_the_manifest_is_refused(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    (outbox_dir / f"{job_id}.md").write_bytes(REPORT.replace(b"All", b"Any"))

    receipt = make_publisher(standin, outbox_dir, state_dir).publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "sha256_mismatch")
    assert standin.items == {}


def test_a_symlinked_report_is_refused(standin, outbox_dir, state_dir, tmp_path):
    job_id = new_job(outbox_dir)
    outside = tmp_path / "outside.md"
    outside.write_bytes(REPORT)
    report = outbox_dir / f"{job_id}.md"
    report.unlink()
    report.symlink_to(outside)

    receipt = make_publisher(standin, outbox_dir, state_dir).publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "report_unreadable")
    assert standin.items == {}


def test_a_symlinked_manifest_is_refused(standin, outbox_dir, state_dir, tmp_path):
    job_id = new_job(outbox_dir)
    manifest = outbox_dir / f"{job_id}.json"
    outside = tmp_path / "manifest.json"
    outside.write_bytes(manifest.read_bytes())
    manifest.unlink()
    manifest.symlink_to(outside)

    receipt = make_publisher(standin, outbox_dir, state_dir).publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "manifest_unreadable")
    assert standin.items == {}


def test_a_report_that_is_not_a_regular_file_is_refused(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    report = outbox_dir / f"{job_id}.md"
    report.unlink()
    os.mkfifo(report)

    receipt = make_publisher(standin, outbox_dir, state_dir).publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "report_unreadable")


@pytest.mark.parametrize(
    "fields",
    [
        {"file": "../escape.md"},
        {"file": "/etc/passwd"},
        {"file": "other.md"},
        {"target": "../summary.md"},
        {"target": "nested/summary.md"},
        {"target": "summary.exe"},
        {"target": ""},
        {"size": -1},
        {"size": "12"},
        {"sha256": "ABC"},
        {"job_id": str(uuid.uuid4())},
        {"seat": "another-seat"},
        {"extra": "field"},
    ],
)
def test_malformed_manifests_are_refused(standin, outbox_dir, state_dir, fields):
    job_id = new_job(outbox_dir)
    rewrite_manifest(outbox_dir, job_id, **fields)

    receipt = make_publisher(standin, outbox_dir, state_dir).publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "manifest_invalid")
    assert standin.items == {}


def test_an_oversized_manifest_is_refused(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    (outbox_dir / f"{job_id}.json").write_bytes(b" " * 65536 + b"{}")

    receipt = make_publisher(standin, outbox_dir, state_dir).publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "manifest_invalid")


def test_a_disallowed_report_type_is_refused(standin, outbox_dir, state_dir):
    job_id = str(uuid.uuid4())
    submit(outbox_dir, job_id=job_id, content=REPORT, extension="sh", target="summary.sh")

    receipt = make_publisher(standin, outbox_dir, state_dir).publish(job_id)

    assert (receipt.outcome, receipt.reason) == ("refused", "manifest_invalid")


@pytest.mark.parametrize("job_id", ["not-a-uuid", "../x", str(uuid.uuid4()).upper()])
def test_a_malformed_job_id_is_refused_before_reading(standin, outbox_dir, state_dir, job_id):
    with pytest.raises(Refused, match="job_id_invalid"):
        make_publisher(standin, outbox_dir, state_dir).publish(job_id)


def test_the_uploaded_bytes_come_from_private_staging(standin, outbox_dir, state_dir):
    job_id = new_job(outbox_dir)
    publisher = make_publisher(standin, outbox_dir, state_dir)

    publisher.publish(job_id)

    staged = state_dir / "staging" / f"{job_id}.md"
    assert staged.read_bytes() == REPORT
    assert staged.stat().st_mode & 0o077 == 0


# Recovery: the outbox is the export queue, outside the /state backup.


def test_replay_reports_an_uncertain_job_and_still_publishes_the_rest(
    standin, outbox_dir, state_dir
):
    jobs = sorted(
        new_job(outbox_dir, content=REPORT + bytes([n]), target=f"summary-{n}.md") for n in range(2)
    )
    standin.lose_next_commit_response = True

    first = make_publisher(standin, outbox_dir, state_dir).replay()

    assert [(r.job_id, r.outcome) for r in first] == [
        (jobs[0], "uncertain"),
        (jobs[1], "published"),
    ]
    second = make_publisher(standin, outbox_dir, state_dir).replay()
    assert [r.outcome for r in second] == ["already_published", "already_published"]
    assert standin.committed_uploads == 2
    assert len(standin.items) == 2


def test_a_restored_outbox_and_a_fresh_publisher_state_lose_no_queued_job(
    standin, outbox_dir, tmp_path
):
    published = new_job(outbox_dir, content=REPORT, target="published.md")
    make_publisher(standin, outbox_dir, tmp_path / "old-publisher").publish(published)
    queued = new_job(outbox_dir, content=REPORT + b"queued\n", target="queued.md")

    receipts = make_publisher(standin, outbox_dir, tmp_path / "replacement-publisher").replay()

    assert {r.job_id: r.outcome for r in receipts} == {
        published: "already_published",
        queued: "published",
    }
    assert sorted(item["name"] for item in standin.items.values()) == ["published.md", "queued.md"]
    assert standin.committed_uploads == 2

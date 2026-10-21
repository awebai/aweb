"""The chain cases: the stored events, the artefacts given, and the report each must produce.

These cases are the test of ``aweb_logs.verify`` and the source of the chain
vector (see ``chain_vector``). Every expected report is stated by hand,
never computed by the verifier under test.
"""

from __future__ import annotations

import copy
import dataclasses
from dataclasses import dataclass, field
from typing import Any

from aweb_naapp.hooks import envelope as hook_envelope
from aweb_naapp.hooks.strictjson import encode_signature
from nacl.signing import SigningKey

from aweb_logs.chain import (
    Checkpoint,
    Genesis,
    Receipt,
    artefact_sha256,
    content_commitment,
    link_for,
    sign_checkpoint,
    sign_receipt,
)
from aweb_logs.verify import Content, StoredEvent

from .fixtures import (
    LOGS_KID,
    LOGS_ORIGIN,
    LOGS_SEED,
    OTHER_LOGS_SEED,
    SECRETS_SEED,
    TEAM_ID,
    did_key,
    signed_event,
)

LOGS_DID = did_key(LOGS_SEED)
OTHER_LOGS_DID = did_key(OTHER_LOGS_SEED)
CREATED_AT = "2026-10-20T11:00:00.000Z"
ISSUED_AT = "2026-10-20T12:10:00.000Z"
KINDS = ("core", "app", "client")
EVENT_IDS = (
    "0192f0c4-6f1e-7c3a-9a51-3d2b8e0f4c11",
    "0192f0c4-7a20-7b51-8e0e-2a64f3c19d02",
    "0192f0c4-8b31-7c62-9f1f-3b75a4d2ae13",
)
ERASE_ACT = "logs.erase:7d0e3f1a-2b4c-4d5e-8f60-718293a4b5c6"


def salt(index: int) -> bytes:
    return bytes((0xC0 + index + i) % 256 for i in range(32))


def received_at(team_seq: int) -> str:
    return f"2026-10-20T12:00:0{team_seq}.500Z"


@dataclass
class ChainCase:
    name: str
    genesis: Genesis
    events: list[StoredEvent]
    report: dict[str, Any]
    receipts: list[tuple[bytes, str]] = field(default_factory=list)
    checkpoints: list[tuple[bytes, str]] = field(default_factory=list)
    receipt_keys: tuple[str, ...] = (LOGS_DID,)
    checkpoint_keys: tuple[str, ...] = (LOGS_DID,)


def genesis(epoch: int = 1, previous: str | None = None) -> Genesis:
    return Genesis(
        team_id=TEAM_ID,
        chain_epoch=epoch,
        logs_origin=LOGS_ORIGIN,
        created_at=CREATED_AT,
        previous_checkpoint_sha256=previous,
    )


def append(start: Genesis, contents: list[Content], *, first_seq: int = 1) -> list[StoredEvent]:
    """Append each content in order, as logs would."""
    events: list[StoredEvent] = []
    prev = start.hash()
    for offset, content in enumerate(contents):
        event = hook_envelope.open_envelope(content.signing_bytes)
        link = link_for(
            event,
            chain_epoch=start.chain_epoch,
            team_seq=first_seq + offset,
            prev_event_hash=prev,
            received_at=received_at(first_seq + offset),
            content_commitment=content_commitment(
                content.salt, content.signing_bytes, content.signature
            ),
        )
        stored = StoredEvent(link=link, event_hash=link.event_hash(), content=content)
        events.append(stored)
        prev = stored.event_hash
    return events


def content(index: int) -> Content:
    kind = KINDS[index]
    signing, signature = signed_event(kind, event_id=EVENT_IDS[index], seq=index + 1)
    producer = hook_envelope.open_envelope(signing).producer_did_key
    return Content(
        salt=salt(index), signing_bytes=signing, signature=signature, producer_did_key=producer
    )


def receipt(event: StoredEvent, event_id: str, *, key_seed: bytes = LOGS_SEED) -> tuple[bytes, str]:
    return sign_receipt(
        SigningKey(key_seed),
        Receipt(
            team_id=event.link.team_id,
            event_id=event_id,
            chain_epoch=event.link.chain_epoch,
            team_seq=event.link.team_seq,
            event_hash=event.event_hash,
            received_at=event.link.received_at,
            logs_origin=LOGS_ORIGIN,
            kid=LOGS_KID,
            did_key=did_key(key_seed),
        ),
    )


def checkpoint(
    epoch: int,
    team_seq: int,
    event_hash: str,
    *,
    previous: str | None = None,
    key_seed: bytes = LOGS_SEED,
) -> tuple[bytes, str]:
    return sign_checkpoint(
        SigningKey(key_seed),
        Checkpoint(
            team_id=TEAM_ID,
            chain_epoch=epoch,
            team_seq=team_seq,
            event_hash=event_hash,
            issued_at=ISSUED_AT,
            logs_origin=LOGS_ORIGIN,
            kid=LOGS_KID,
            did_key=did_key(key_seed),
            previous_checkpoint_sha256=previous,
        ),
    )


def relink(start: Genesis, events: list[StoredEvent]) -> list[StoredEvent]:
    """Renumber and rehash events from the genesis on: what anyone with database
    access but not logs' key can do."""
    rebuilt: list[StoredEvent] = []
    prev = start.hash()
    for offset, event in enumerate(events):
        link = dataclasses.replace(event.link, team_seq=offset + 1, prev_event_hash=prev)
        rebuilt.append(dataclasses.replace(event, link=link, event_hash=link.event_hash()))
        prev = rebuilt[-1].event_hash
    return rebuilt


def _intact(**extra: Any) -> dict[str, Any]:
    return {"intact": True, "missing": [], "purged": [], "contradicted": [], **extra}


def _broken(team_seq: int, reason: str, **extra: Any) -> dict[str, Any]:
    report = {"intact": False, "missing": [], "purged": [], "contradicted": [], **extra}
    report["first_break"] = {"team_seq": team_seq, "reason": reason}
    return report


def _altered(stored: Content) -> Content:
    """The content with its envelope's payload changed after the producer signed it."""
    altered = stored.signing_bytes.replace(b'"new_status":"in_progress"', b'"new_status":"closed"')
    return dataclasses.replace(stored, signing_bytes=altered)


def cases() -> list[ChainCase]:
    start = genesis()
    contents = [content(i) for i in range(3)]
    chain = append(start, contents)
    receipts = [receipt(event, EVENT_IDS[i]) for i, event in enumerate(chain)]
    head = checkpoint(1, 3, chain[-1].event_hash)
    empty_checkpoint = checkpoint(1, 0, start.hash())
    linked_head = checkpoint(
        1, 3, chain[-1].event_hash, previous=artefact_sha256(empty_checkpoint[0])
    )

    second = genesis(2, previous=artefact_sha256(head[0]))
    second_chain = append(second, contents[:1])

    purged = copy.copy(chain)
    purged[1] = dataclasses.replace(chain[1], content=None, purge_act=ERASE_ACT)

    altered = copy.copy(chain)
    altered[0] = dataclasses.replace(
        chain[0],
        content=_altered(contents[0]),
    )

    skeleton = copy.copy(chain)
    skeleton[1] = dataclasses.replace(
        chain[1], link=dataclasses.replace(chain[1].link, hook="post-governance-hook")
    )

    swapped = [chain[0], chain[2], chain[1]]
    naive_reorder = [
        dataclasses.replace(swapped[1], link=dataclasses.replace(swapped[1].link, team_seq=2)),
        dataclasses.replace(swapped[2], link=dataclasses.replace(swapped[2].link, team_seq=3)),
    ]
    naive_reorder.insert(0, chain[0])
    rewritten_reorder = relink(start, swapped)

    gap = [chain[0], chain[2]]

    # The producer's signature cannot be rebuilt, so an altered envelope with a
    # recomputed commitment and chain still fails provenance.
    forged_provenance = append(start, [_altered(contents[0]), contents[1], contents[2]])

    wrong_key_evidence = copy.copy(chain)
    wrong_key_evidence[1] = dataclasses.replace(
        chain[1],
        content=dataclasses.replace(contents[1], producer_did_key=did_key(SECRETS_SEED[::-1])),
    )

    missing_content = copy.copy(chain)
    missing_content[2] = dataclasses.replace(chain[2], content=None)

    duplicate = [chain[0], chain[1], chain[1], chain[2]]

    other_team = copy.copy(chain)
    other_link = dataclasses.replace(chain[1].link, team_id="other:example.com")
    other_team[1] = dataclasses.replace(
        chain[1], link=other_link, event_hash=other_link.event_hash()
    )

    def rehashed(event: StoredEvent, **link_changes: Any) -> StoredEvent:
        link = dataclasses.replace(event.link, **link_changes)
        return dataclasses.replace(event, link=link, event_hash=link.event_hash())

    # The normative break order, pinned pair by pair: each case puts two
    # adjacent faults on one event, so the earlier check is the one reported.
    # content_missing and commitment_mismatch never meet: without content
    # there is no commitment to check.
    duplicate_of_another_team = [
        chain[0],
        chain[1],
        rehashed(chain[1], team_id="other:example.com"),
        chain[2],
    ]
    another_team_unlinked = copy.copy(chain)
    another_team_unlinked[1] = rehashed(
        chain[1], team_id="other:example.com", prev_event_hash=chain[2].event_hash
    )
    wrong_hash_without_content = copy.copy(chain)
    wrong_hash_without_content[2] = dataclasses.replace(
        chain[2], content=None, event_hash=chain[1].event_hash
    )
    # With content retained, content_missing drops out of the order and the
    # event hash comes directly before the commitment.
    wrong_hash_and_altered_content = copy.copy(chain)
    wrong_hash_and_altered_content[0] = dataclasses.replace(
        chain[0], content=_altered(contents[0]), event_hash=chain[1].event_hash
    )
    wrong_key_and_skeleton = copy.copy(chain)
    wrong_key_and_skeleton[0] = rehashed(
        dataclasses.replace(
            chain[0],
            content=dataclasses.replace(contents[0], producer_did_key=did_key(SECRETS_SEED[::-1])),
        ),
        hook="post-governance-hook",
    )
    skeleton_only = copy.copy(chain)
    skeleton_only[0] = rehashed(chain[0], hook="post-governance-hook")

    forged_by_other_key = checkpoint(1, 3, chain[-1].event_hash, key_seed=OTHER_LOGS_SEED)
    claimed_logs_key = (
        head[0],
        encode_signature(SigningKey(OTHER_LOGS_SEED).sign(head[0]).signature),
    )
    wrong_hash_checkpoint = checkpoint(1, 2, chain[2].event_hash)
    other_team_receipt = sign_receipt(
        SigningKey(LOGS_SEED),
        Receipt(
            team_id="other:example.com",
            event_id=EVENT_IDS[0],
            chain_epoch=1,
            team_seq=1,
            event_hash=chain[0].event_hash,
            received_at=chain[0].link.received_at,
            logs_origin=LOGS_ORIGIN,
            kid=LOGS_KID,
            did_key=LOGS_DID,
        ),
    )
    ahead_checkpoint = checkpoint(1, 4, chain[-1].event_hash)

    def receipt_naming(**changes: Any) -> tuple[bytes, str]:
        """A receipt for the chain's second event with some of its fields changed."""
        fields = {
            "team_id": TEAM_ID,
            "event_id": EVENT_IDS[1],
            "chain_epoch": 1,
            "team_seq": 2,
            "event_hash": chain[1].event_hash,
            "received_at": chain[1].link.received_at,
            "logs_origin": LOGS_ORIGIN,
            "kid": LOGS_KID,
            "did_key": LOGS_DID,
        }
        return sign_receipt(SigningKey(LOGS_SEED), Receipt(**{**fields, **changes}))

    receipt_for_another_event = receipt_naming(event_id=EVENT_IDS[0])
    receipt_at_another_time = receipt_naming(received_at="2026-10-20T12:00:09.500Z")

    return [
        ChainCase(
            "intact_chain_of_three_producers",
            start,
            chain,
            _intact(),
            receipts=receipts,
            checkpoints=[empty_checkpoint, linked_head],
        ),
        ChainCase("empty_epoch", start, [], _intact(), checkpoints=[empty_checkpoint]),
        ChainCase("second_epoch_records_the_first", second, second_chain, _intact()),
        ChainCase(
            "purged_stub_still_verifies",
            start,
            purged,
            _intact(purged=[{"from": 2, "to": 2, "act": ERASE_ACT}]),
            receipts=receipts,
            checkpoints=[head],
        ),
        ChainCase("altered_content", start, altered, _broken(1, "commitment_mismatch")),
        ChainCase("altered_skeleton", start, skeleton, _broken(2, "event_hash_mismatch")),
        ChainCase("reorder", start, naive_reorder, _broken(2, "prev_hash_mismatch")),
        ChainCase(
            "reorder_rehashed_contradicts_its_witnesses",
            start,
            rewritten_reorder,
            {
                "intact": False,
                "missing": [],
                "purged": [],
                "contradicted": [
                    {"artefact": "receipt", "index": 1, "reason": "hash_mismatch"},
                    {"artefact": "receipt", "index": 2, "reason": "hash_mismatch"},
                    {"artefact": "checkpoint", "index": 0, "reason": "hash_mismatch"},
                ],
            },
            receipts=receipts,
            checkpoints=[head],
        ),
        ChainCase(
            "gap",
            start,
            gap,
            {
                "intact": False,
                "missing": [[2, 2]],
                "purged": [],
                "contradicted": [{"artefact": "receipt", "index": 0, "reason": "not_in_chain"}],
            },
            receipts=[receipts[1]],
        ),
        ChainCase(
            "rewritten_envelope_fails_provenance",
            start,
            forged_provenance,
            _broken(1, "provenance_invalid"),
        ),
        ChainCase(
            "key_evidence_is_not_the_producer",
            start,
            wrong_key_evidence,
            _broken(2, "provenance_invalid"),
        ),
        ChainCase(
            "content_gone_without_an_act", start, missing_content, _broken(3, "content_missing")
        ),
        ChainCase("duplicate_sequence", start, duplicate, _broken(2, "sequence_duplicate")),
        ChainCase("event_of_another_team", start, other_team, _broken(2, "wrong_chain")),
        ChainCase(
            "duplicate_comes_before_wrong_chain",
            start,
            duplicate_of_another_team,
            _broken(2, "sequence_duplicate"),
        ),
        ChainCase(
            "wrong_chain_comes_before_a_broken_link",
            start,
            another_team_unlinked,
            _broken(2, "wrong_chain"),
        ),
        ChainCase(
            "wrong_event_hash_comes_before_missing_content",
            start,
            wrong_hash_without_content,
            _broken(3, "event_hash_mismatch"),
        ),
        ChainCase(
            "wrong_event_hash_comes_before_altered_content",
            start,
            wrong_hash_and_altered_content,
            _broken(1, "event_hash_mismatch"),
        ),
        ChainCase(
            "provenance_comes_before_the_skeleton",
            start,
            wrong_key_and_skeleton,
            _broken(1, "provenance_invalid"),
        ),
        ChainCase(
            "skeleton_that_disagrees_with_its_envelope",
            start,
            skeleton_only,
            _broken(1, "skeleton_mismatch"),
        ),
        ChainCase(
            "forged_checkpoints",
            start,
            chain,
            {
                "intact": False,
                "missing": [],
                "purged": [],
                "contradicted": [
                    {"artefact": "checkpoint", "index": 0, "reason": "signature_invalid"},
                    {"artefact": "checkpoint", "index": 1, "reason": "signature_invalid"},
                    {"artefact": "checkpoint", "index": 2, "reason": "hash_mismatch"},
                    {"artefact": "checkpoint", "index": 3, "reason": "not_in_chain"},
                ],
            },
            checkpoints=[
                forged_by_other_key,
                claimed_logs_key,
                wrong_hash_checkpoint,
                ahead_checkpoint,
            ],
        ),
        ChainCase(
            "receipt_names_another_event_at_its_sequence",
            start,
            chain,
            {
                "intact": False,
                "missing": [],
                "purged": [],
                "contradicted": [
                    {"artefact": "receipt", "index": 0, "reason": "event_mismatch"},
                    {"artefact": "receipt", "index": 1, "reason": "event_mismatch"},
                ],
            },
            receipts=[receipt_for_another_event, receipt_at_another_time],
        ),
        ChainCase(
            "purged_event_still_binds_its_receipt_time",
            start,
            purged,
            {
                "intact": False,
                "missing": [],
                "purged": [{"from": 2, "to": 2, "act": ERASE_ACT}],
                "contradicted": [{"artefact": "receipt", "index": 1, "reason": "event_mismatch"}],
            },
            receipts=[receipt_for_another_event, receipt_at_another_time],
        ),
        ChainCase(
            "receipt_for_another_team",
            start,
            chain,
            {
                "intact": False,
                "missing": [],
                "purged": [],
                "contradicted": [{"artefact": "receipt", "index": 0, "reason": "wrong_chain"}],
            },
            receipts=[other_team_receipt],
        ),
    ]

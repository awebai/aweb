"""Observed sequence evidence is distinct from chain integrity and delivery completeness."""

from __future__ import annotations

import copy
from dataclasses import replace
from uuid import uuid4

import pytest
from aweb_naapp.hooks import envelope

from aweb_logs.chain import Genesis, content_commitment, link_for
from aweb_logs.verify import Content, StoredEvent, verify_chain, verify_deliveries

from .fixtures import CORE_SEED, LOGS_ORIGIN, SECRETS_SEED, TEAM_ID, did_key, seed, signed_event

AT = "2026-10-20T12:00:01.000Z"
ACTIVE = "2026-10-20T11:59:00.000Z"
GENESIS = Genesis(team_id=TEAM_ID, chain_epoch=1, logs_origin=LOGS_ORIGIN, created_at=ACTIVE)


def _binding(event, kind, binding_id):
    producer = event.fields["producer"]
    return {
        "binding_id": binding_id, "team_id": TEAM_ID, "kind": kind,
        "catalog_id": "aweb.hooks", "catalog_version": 1, "hook": event.hook,
        "app_id": "logs" if kind == "registration" else producer["app_id"],
        "origin": LOGS_ORIGIN if kind == "registration" else producer["origin"],
        "installation_id": "logs-install" if kind == "registration" else producer["installation_id"],
        "generation": 1 if kind == "registration" else producer["generation"],
        "digest": "sha256:" + "a" * 64, "method": "POST", "path": "/v1/hooks/ingest",
        "active_from": ACTIVE, "state": "active", "revoked_at": None,
    }


def _events(seqs, *, kind="app", change=None):
    result = []
    prev = GENESIS.hash()
    for team_seq, seq in enumerate(seqs, 1):
        signing, signature = signed_event(kind, seq=seq, event_id=str(uuid4()), occurred_at=AT)
        fields = envelope.open_envelope(signing).fields
        if change is not None:
            change(team_seq, fields)
            signing, signature = envelope.sign(SECRETS_SEED if kind == "app" else CORE_SEED, fields)
        event = envelope.verify(signing, signature, team_id=TEAM_ID)
        admission = {"registration": _binding(event, "registration", "registration-1")}
        if kind == "app":
            admission["production"] = _binding(event, "production", "production-1")
        if kind == "core":
            admission["server_url"] = event.fields["producer"]["origin"]
        evidence = {"did_key": event.producer_did_key, "admissions": [admission]}
        salt = seed(team_seq)
        link = link_for(event, chain_epoch=1, team_seq=team_seq, prev_event_hash=prev,
                        received_at=AT, content_commitment=content_commitment(salt, signing, signature))
        stored = StoredEvent(link, link.event_hash(), Content(salt, signing, signature, event.producer_did_key),
                             key_evidence=evidence)
        result.append(stored)
        prev = stored.event_hash
    return result


@pytest.mark.parametrize("kind", ["app", "core"])
def test_only_authenticated_internal_holes_are_reported(kind):
    events = _events([40, 43], kind=kind)
    report = verify_deliveries(GENESIS, events).to_json()
    assert report["scope"] == "observed_internal_only"
    assert [(g["from"], g["to"]) for g in report["gaps"]] == [(41, 42)]
    assert report["gaps"][0]["registration_id"] == "registration-1"
    assert report["sequence_conflicts"] == report["unassessed"] == []
    # A delivery hole does not mean the receipt chain itself was edited.
    assert verify_chain(GENESIS, events, receipt_keys=frozenset(), checkpoint_keys=frozenset()).intact


def test_late_events_fill_holes_without_inventing_a_restart():
    assert verify_deliveries(GENESIS, _events([43, 40, 42, 41])).to_json()["gaps"] == []


def test_key_rotation_does_not_hide_an_internal_hole():
    events = _events([40, 43])
    event = events[1]
    fields = envelope.open_envelope(event.content.signing_bytes).fields
    fields["producer"].update(kid="rotated", did_key=did_key(seed(200)))
    signing, signature = envelope.sign(seed(200), fields)
    key = fields["producer"]["did_key"]
    content = replace(event.content, signing_bytes=signing, signature=signature, producer_did_key=key)
    link = replace(event.link, content_commitment=content_commitment(content.salt, signing, signature))
    events[1] = replace(event, content=content, link=link, event_hash=link.event_hash())
    assert len(verify_deliveries(GENESIS, events).gaps) == 1


@pytest.mark.parametrize("boundary", ["generation", "installation", "production", "registration", "activation"])
def test_observation_does_not_bridge_provenance_intervals(boundary):
    def change(i, fields):
        if i == 2 and boundary == "generation":
            fields["producer"]["generation"] += 1
        if i == 2 and boundary == "installation":
            fields["producer"]["installation_id"] = str(uuid4())
    events = _events([40, 43], change=change)
    evidence = copy.deepcopy(events[1].key_evidence)
    admission = evidence["admissions"][0]
    if boundary in ("production", "registration"):
        admission[boundary]["binding_id"] += "-new"
    if boundary == "activation":
        admission["production"]["active_from"] = "2026-10-20T12:00:00.000Z"
    events[1] = replace(events[1], key_evidence=evidence)
    assert verify_deliveries(GENESIS, events).gaps == ()


def test_distinct_authenticated_events_reusing_a_sequence_are_an_inconsistency():
    events = _events([40, 40])
    report = verify_deliveries(GENESIS, events).to_json()
    conflict, = report["sequence_conflicts"]
    assert conflict["seq"] == 40
    assert set(conflict["event_ids"]) == {
        envelope.open_envelope(e.content.signing_bytes).event_id for e in events
    }
    assert report["gaps"] == []


@pytest.mark.parametrize("uncertainty", ["legacy", "purged", "tampered", "wrong_production"])
def test_uncertain_content_or_authority_cannot_establish_a_hole(uncertainty):
    events = _events([40, 41, 43])
    middle = events[1]
    if uncertainty == "legacy":
        middle = replace(middle, key_evidence={"did_key": middle.content.producer_did_key})
    elif uncertainty == "purged":
        middle = replace(middle, content=None, purge_act="erase:1")
    elif uncertainty == "tampered":
        middle = replace(middle, content=replace(middle.content, signature=events[0].content.signature))
    else:
        evidence = copy.deepcopy(middle.key_evidence)
        evidence["admissions"][0]["production"]["installation_id"] = "another-install"
        middle = replace(middle, key_evidence=evidence)
    events[1] = middle
    report = verify_deliveries(GENESIS, events)
    assert report.gaps == ()
    assert report.unassessed


def test_client_events_do_not_have_a_required_sequence():
    assert verify_deliveries(GENESIS, _events([1, 10], kind="client")).to_json() == {
        "scope": "observed_internal_only", "gaps": [], "sequence_conflicts": [], "unassessed": [],
    }

"""The protected round trip's fault injector: the front withholds the 2xx
answer to one request (a signer's prepare, an app's owner-act delivery)."""

import base64
import hashlib
import json
from pathlib import Path

import pytest
from protected_round_trip import (
    AnswerDrop,
    Designation,
    Holding,
    SignedAct,
    assert_designated,
    assert_one_effect,
    assert_unchanged,
    credential_sha256,
    designation_snapshot,
    read_only_psql,
    receiver_snapshot,
    signed_act,
)

SITES = {
    "aweb.lf.test": "aweb:8000",
    "console.secrets.lf.test": "secrets:8770",
    "api.logs.lf.test": "logs:8765",
}
WITHOUT_SIGNER = "{\n  auto_https off\n}\n" + "".join(
    f"{host}:443 {{\n  tls /tls/c.pem /tls/k.pem\n  reverse_proxy {target}\n}}\n" for host, target in SITES.items())
WITH_SIGNER = WITHOUT_SIGNER + "signer.lf.test:443 {\n  tls /tls/c.pem /tls/k.pem\n  reverse_proxy signer:8080\n}\n"


def drop(tmp_path, text, host="signer.lf.test", path="/protected-operations", upstream="signer:8080"):
    rendered = tmp_path / "Caddyfile"
    rendered.write_text(text)
    reloads = []
    answer = AnswerDrop(rendered, host, "POST", path, upstream, lambda: reloads.append(rendered.read_text()))
    return rendered, reloads, answer


def test_the_drop_uses_the_front_as_rendered_when_it_starts_not_when_built(tmp_path):
    rendered, reloads, answer = drop(tmp_path, WITHOUT_SIGNER)
    rendered.write_text(WITH_SIGNER)
    with answer:
        dropped = rendered.read_text()
        assert dropped.count("@dropped {") == 1
        assert "signer.lf.test:443 {\n  @dropped {\n    method POST\n    path /protected-operations\n  }\n" in dropped
        assert "  reverse_proxy @dropped signer:8080 {\n" in dropped and dropped.count("abort") == 1
        # Every other site, and the host's own proxy, are untouched.
        assert dropped.replace(dropped[dropped.index("  @dropped {"):dropped.index("  tls /tls/c.pem", dropped.index(
            "  @dropped {"))], "") == WITH_SIGNER
        assert reloads == [dropped]
    assert rendered.read_text() == WITH_SIGNER and reloads[-1] == WITH_SIGNER and len(reloads) == 2


def test_the_drop_withholds_an_apps_owner_act_answer_on_its_console_host(tmp_path):
    rendered, reloads, answer = drop(tmp_path, WITH_SIGNER, host="console.secrets.lf.test",
                                     path="/.well-known/aweb-owner-act", upstream="secrets:8770")
    with answer:
        dropped = rendered.read_text()
        assert "console.secrets.lf.test:443 {\n  @dropped {\n    method POST\n    path /.well-known/aweb-owner-act\n" in dropped
        assert "  reverse_proxy @dropped secrets:8770 {\n" in dropped
        assert "signer.lf.test:443 {\n  tls" in dropped
    assert rendered.read_text() == WITH_SIGNER


def test_the_front_is_restored_when_the_step_under_the_drop_fails(tmp_path):
    rendered, reloads, answer = drop(tmp_path, WITH_SIGNER)
    with pytest.raises(RuntimeError, match="the step failed"):
        with answer:
            raise RuntimeError("the step failed")
    assert rendered.read_text() == WITH_SIGNER and reloads[-1] == WITH_SIGNER


@pytest.mark.parametrize("text", [
    WITHOUT_SIGNER,
    WITH_SIGNER + "signer.lf.test:443 {\n  respond 200\n}\n",
])
def test_a_front_without_exactly_one_site_for_the_host_is_refused_and_left_alone(tmp_path, text):
    rendered, reloads, answer = drop(tmp_path, text)
    with pytest.raises(SystemExit, match="signer.lf.test"):
        with answer:
            pytest.fail("the step ran under a drop that was never installed")
    assert rendered.read_text() == text and reloads == []


def test_a_drop_cannot_start_twice(tmp_path):
    rendered, reloads, answer = drop(tmp_path, WITH_SIGNER)
    with answer:
        with pytest.raises(SystemExit, match="already"):
            answer.__enter__()
    assert rendered.read_text() == WITH_SIGNER


# --- the signed act a committed operation names, and one effect at the app


ACT = {"v": 1, "type": "aweb.owner-act/1", "act": "human-role.revoke", "team_id": "lfteam:lf.test",
       "aud": "https://console.secrets.lf.test", "team_key_did": "did:key:z6Mk", "subject": {"role": "secrets.owner"},
       "issued_at": "2026-11-13T12:00:00Z", "expires_at": "2026-11-13T12:05:00Z", "nonce": "n0nce"}
SIGNING = b"aweb.owner-act/1\n" + json.dumps(ACT, separators=(",", ":"), sort_keys=True).encode()


def test_the_signed_act_is_named_by_the_hash_of_its_exact_signing_bytes_and_its_nonce():
    act = signed_act(base64.b64encode(SIGNING).decode())
    assert act == SignedAct(nonce="n0nce", sha256=hashlib.sha256(SIGNING).hexdigest(), act="human-role.revoke",
                            expires_at="2026-11-13T12:05:00Z")


@pytest.mark.parametrize("signing", [
    base64.b64encode(b"aweb.human-credential/1\n{}").decode(),
    base64.b64encode(SIGNING).decode().rstrip("="),
    base64.b64encode(SIGNING).decode()[:20] + "\n" + base64.b64encode(SIGNING).decode()[20:],
])
def test_signing_bytes_not_an_owner_act_or_not_strict_base64_are_refused(signing):
    with pytest.raises(SystemExit):
        signed_act(signing)


H = hashlib.sha256(SIGNING).hexdigest()
SUBJECT = "b3-subject"
BASELINE = {"assignments": 1, "holding": {"ended": False, "subject": SUBJECT, "superseded": False, "usable_keys": 1},
            "revision": 7, "nonces": 3, "authorities": 2, "nonce_rows": [], "authority_rows": []}
FIRST = {"assignments": 0, "holding": {"ended": True, "subject": SUBJECT, "superseded": True, "usable_keys": 0},
         "revision": 8, "nonces": 4, "authorities": 3,
         "nonce_rows": [{"nonce": "n0nce", "act_sha256": H}],
         "authority_rows": [{"subject": SUBJECT, "authority": "owner_act", "commitment": H, "signing_sha256": H,
                             "event_id": "e1", "kind": "post-governance-hook", "act": "role.revoked",
                             "event_act_sha256": H}]}
ACT_SIGNED = SignedAct(nonce="n0nce", sha256=H, act="human-role.revoke", expires_at="2026-11-13T12:05:00Z")


def test_one_revoke_and_its_exact_replay_are_one_effect():
    assert_one_effect(BASELINE, FIRST, dict(FIRST), ACT_SIGNED)


def mutated(snapshot, **changes):
    out = json.loads(json.dumps(snapshot))
    out.update(changes)
    return out


@pytest.mark.parametrize("first, replay, seam", [
    # The first delivery took no effect.
    (mutated(FIRST, assignments=1), FIRST, "first application"),
    (mutated(FIRST, revision=7), FIRST, "first application"),
    (mutated(FIRST, nonce_rows=[], nonces=3), FIRST, "first application"),
    (mutated(FIRST, authority_rows=[], authorities=2), FIRST, "first application"),
    # Another act's row, not this one's.
    (mutated(FIRST, nonce_rows=[{"nonce": "n0nce", "act_sha256": "0" * 64}]), FIRST, "first application"),
    # The replay took a second effect: a fresh act, not this one again.
    (FIRST, mutated(FIRST, revision=9), "replay"),
    (FIRST, mutated(FIRST, nonces=5), "replay"),
    (FIRST, mutated(FIRST, authorities=4), "replay"),
    (FIRST, mutated(FIRST, authority_rows=FIRST["authority_rows"] * 2), "replay"),
])
def test_a_missing_first_effect_or_a_second_effect_is_named_by_its_seam(first, replay, seam):
    with pytest.raises(AssertionError, match=seam):
        assert_one_effect(BASELINE, first, replay, ACT_SIGNED)


def test_a_baseline_taken_after_the_effect_is_refused():
    with pytest.raises(AssertionError, match="baseline"):
        assert_one_effect(FIRST, FIRST, FIRST, ACT_SIGNED)


# --- the receiver snapshot: what it reads, and how


HOLDING = Holding(app_id="lfteam-secrets", installation_id="4fead199-b779", generation=1, team_id="lfteam:lf.test",
                  role="secrets.owner", principal="did:aw:approver")


def snapshot_of(rows: dict):
    queries = []

    def query(select: str) -> str:
        queries.append(select)
        return json.dumps(rows)
    return queries, query


def test_the_snapshot_reads_one_holding_scoped_by_installation_team_role_and_principal():
    queries, query = snapshot_of({"assignments": 1, "holdings": [{"subject": "s", "ended": False}], "revision": 3,
                                  "nonces": 0, "nonce_rows": [], "authorities": 0, "authority_rows": []})
    snapshot = receiver_snapshot(query, HOLDING, "n0nce", schema="public")
    assert snapshot["holding"] == {"subject": "s", "ended": False} and "holdings" not in snapshot
    (select,) = queries
    for literal in ("'lfteam-secrets'", "'4fead199-b779'", "'1'", "'lfteam:lf.test'", "'secrets.owner'",
                    "'did:aw:approver'", "'n0nce'"):
        assert literal in select, literal
    assert "h.ended_in IS NULL AND p.superseded_at IS NULL" in select and "a.commitment = NULL" in select
    assert "BEGIN" not in select and "COMMIT" not in select


def test_a_later_snapshot_reads_the_captured_subject_and_this_acts_rows():
    queries, query = snapshot_of({"holdings": [{"subject": "s"}]})
    receiver_snapshot(query, HOLDING, "n0nce", subject="s", act_sha256="a" * 64, schema="public")
    (select,) = queries
    assert "p.subject = 's'" in select and "ended_in IS NULL" not in select
    assert f"a.commitment = '{'a' * 64}'" in select


@pytest.mark.parametrize("holdings", [[], [{"subject": "s"}, {"subject": "t"}]])
def test_a_snapshot_finding_no_holding_or_several_is_refused(holdings):
    _, query = snapshot_of({"holdings": holdings})
    with pytest.raises(SystemExit, match="holdings"):
        receiver_snapshot(query, HOLDING, "n0nce", schema="public")


@pytest.mark.parametrize("value", ["it's", "a b", "x;DROP", ""])
def test_a_value_that_is_not_a_plain_identifier_is_never_quoted_into_the_query(value):
    _, query = snapshot_of({"holdings": [{"subject": "s"}]})
    with pytest.raises(SystemExit, match="receiver snapshot"):
        receiver_snapshot(query, HOLDING, value, schema="public")


def test_the_snapshot_reads_the_apps_own_schema():
    queries, query = snapshot_of({"holdings": [{"subject": "s"}]})
    receiver_snapshot(query, HOLDING, "n0nce", schema="secrets")
    (select,) = queries
    for table in ("role_assignments", "role_holdings", "passkey_approvers", "passkey_credentials", "config_revisions",
                  "owner_act_nonces", "credential_narrowing_authority", "outbox_events"):
        assert f"secrets.{table}" in select, table
    assert "public." not in select


@pytest.mark.parametrize("schema", ["Secrets", "a;b", "public.x", ""])
def test_a_schema_that_is_not_a_plain_identifier_is_refused(schema):
    _, query = snapshot_of({"holdings": [{"subject": "s"}]})
    with pytest.raises(SystemExit, match="schema"):
        receiver_snapshot(query, HOLDING, "n0nce", schema=schema)


def test_the_snapshot_runs_read_only_in_one_session():
    args = read_only_psql("secrets", "secrets", "SELECT 1")
    assert args[:5] == ["psql", "-U", "secrets", "-d", "secrets"] and "-q" in args and "-At" in args
    commands = [args[i + 1] for i, arg in enumerate(args) if arg == "-c"]
    assert commands == ["BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY", "SELECT 1", "COMMIT"]


# --- a designation's effect at the app (no signer: the owner signs it locally)


VECTORS = json.loads((Path(__file__).resolve().parents[3] / "docs/vectors/owner-act-delivery-v1.json").read_text())


@pytest.mark.parametrize("case", VECTORS["credential_cases"], ids=lambda case: case["name"])
def test_a_credential_is_named_by_its_published_digest(case):
    assert credential_sha256(case["credential"]) == case["credential_sha256"]


CREDENTIAL = VECTORS["credential_cases"][0]["credential"]
CONTACT = "approver@h.test"
CONTACT_SHA256 = hashlib.sha256(CONTACT.encode()).hexdigest()
DESIGNATION = Designation(holding=HOLDING, audience="https://console.secrets.lf.test",
                          credential_sha256=credential_sha256(CREDENTIAL), contact=CONTACT)
DESIGNATE = {"v": 1, "type": "aweb.owner-act/1", "act": "human-role.designate", "team_id": "lfteam:lf.test",
             "aud": "https://console.secrets.lf.test", "team_key_did": "did:key:z6Mk",
             "subject": {"app_id": "lfteam-secrets", "installation_id": "4fead199-b779", "role": "secrets.owner",
                         "principal": "did:aw:approver", "credential_sha256": credential_sha256(CREDENTIAL),
                         "notice_contact_sha256": CONTACT_SHA256},
             "issued_at": "2026-11-13T12:00:00Z", "expires_at": "2026-11-13T12:05:00Z", "nonce": "d3s1gn"}


def designate_signing(document=DESIGNATE) -> bytes:
    return b"aweb.owner-act/1\n" + json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def authorization(signing=None, **changes) -> dict:
    signing = signing or designate_signing()
    digest = hashlib.sha256(signing).hexdigest()
    row = {"subject": SUBJECT, "authority": "owner_act", "commitment": digest, "signing_sha256": digest,
           "signing_hex": signing.hex(), "principal": "did:aw:approver", "notice_contact_sha256": CONTACT_SHA256,
           "credential_sha256": credential_sha256(CREDENTIAL)}
    row.update(changes)
    return row


def designation_rows(**changes) -> dict:
    """What the app's database returns after the designation, with changes."""
    rows = {"assignments": 1, "holdings": [{"subject": SUBJECT, "contact": CONTACT}], "revision": 8, "nonces": 4,
            "authorizations": 3, "authorization_rows": [authorization()],
            "nonce_rows": [{"nonce": "d3s1gn", "act_sha256": hashlib.sha256(designate_signing()).hexdigest()}]}
    rows.update(changes)
    return rows


UNDESIGNATED = {"assignments": 0, "holdings": [], "revision": 7, "nonces": 3, "authorizations": 2,
                "authorization_rows": [], "nonce_rows": []}


def snapshot(rows: dict) -> dict:
    _, query = snapshot_of(rows)
    return designation_snapshot(query, HOLDING, schema="public")


def test_the_designation_snapshot_reads_the_holdings_scoped_records_in_the_apps_schema():
    queries, query = snapshot_of(UNDESIGNATED)
    designation_snapshot(query, HOLDING, schema="secrets")
    (select,) = queries
    for literal in ("'lfteam-secrets'", "'4fead199-b779'", "'1'", "'lfteam:lf.test'", "'secrets.owner'",
                    "'did:aw:approver'"):
        assert literal in select, literal
    for table in ("role_assignments", "role_holdings", "passkey_approvers", "config_revisions", "owner_act_nonces",
                  "credential_authorizations"):
        assert f"secrets.{table}" in select, table
    assert "public." not in select and "credential_narrowing_authority" not in select and "outbox" not in select


def test_the_snapshot_keeps_the_signed_document_and_its_digest_not_the_signing_bytes():
    taken = snapshot(designation_rows())
    (row,) = taken["authorization_rows"]
    assert "signing_hex" not in row and row["document"] == DESIGNATE
    assert row["signing_sha256"] == hashlib.sha256(designate_signing()).hexdigest()


def test_one_designation_is_one_holding_bound_to_the_exact_act_the_owner_signed():
    assert_designated(snapshot(UNDESIGNATED), snapshot(designation_rows()), DESIGNATION)


def changed_document(**changes) -> dict:
    document = json.loads(json.dumps(DESIGNATE))
    for key, value in changes.items():
        if key in document["subject"]:
            document["subject"][key] = value
        else:
            document[key] = value
    return document


def signed_as(document: dict) -> dict:
    signing = designate_signing(document)
    return designation_rows(authorization_rows=[authorization(signing)], nonce_rows=[
        {"nonce": document["nonce"], "act_sha256": hashlib.sha256(signing).hexdigest()}])


@pytest.mark.parametrize("after", [
    # Not held, or held twice, or held with another contact.
    designation_rows(assignments=0),
    designation_rows(holdings=[]),
    designation_rows(holdings=[{"subject": SUBJECT, "contact": "other@h.test"}]),
    # No revision, nonce or authorization for it.
    designation_rows(revision=7),
    designation_rows(nonces=3),
    designation_rows(authorizations=2),
    designation_rows(authorization_rows=[]),
    designation_rows(nonce_rows=[]),
    # An authorization that is not this holding's, or not the owner's act.
    designation_rows(authorization_rows=[authorization(subject="another")]),
    designation_rows(authorization_rows=[authorization(authority="passkey_session")]),
    designation_rows(authorization_rows=[authorization(commitment="0" * 64)]),
    # A commitment and nonce row that agree, but not with the retained signing bytes.
    designation_rows(authorization_rows=[authorization(commitment="0" * 64)],
                     nonce_rows=[{"nonce": "d3s1gn", "act_sha256": "0" * 64}]),
    designation_rows(authorization_rows=[authorization(principal="did:aw:other")]),
    designation_rows(authorization_rows=[authorization(notice_contact_sha256="0" * 64)]),
    designation_rows(authorization_rows=[authorization(credential_sha256="0" * 64)]),
    # The nonce row is another act's, or another nonce.
    designation_rows(nonce_rows=[{"nonce": "d3s1gn", "act_sha256": "0" * 64}]),
    designation_rows(nonce_rows=[{"nonce": "other", "act_sha256": hashlib.sha256(designate_signing()).hexdigest()}]),
    # A self-consistent act that is not the one the owner meant.
    signed_as(changed_document(act="human-role.revoke")),
    signed_as(changed_document(team_id="other:lf.test")),
    signed_as(changed_document(aud="https://console.other.lf.test")),
    signed_as(changed_document(app_id="other-secrets")),
    signed_as(changed_document(installation_id="other")),
    signed_as(changed_document(role="secrets.reader")),
    signed_as(changed_document(principal="did:aw:other")),
    signed_as(changed_document(credential_sha256="0" * 64)),
    signed_as(changed_document(notice_contact_sha256="0" * 64)),
])
def test_a_designation_not_bound_to_the_owners_exact_act_is_refused(after):
    with pytest.raises(AssertionError, match="designation"):
        assert_designated(snapshot(UNDESIGNATED), snapshot(after), DESIGNATION)


def test_a_baseline_that_already_holds_the_role_is_refused():
    with pytest.raises(AssertionError, match="baseline"):
        assert_designated(snapshot(designation_rows()), snapshot(designation_rows()), DESIGNATION)


def test_a_refused_duplicate_leaves_every_scoped_record_as_the_designation_left_it():
    after = snapshot(designation_rows())
    assert_unchanged(after, snapshot(designation_rows()))
    for changed in (designation_rows(revision=9), designation_rows(nonces=5), designation_rows(authorizations=4),
                    designation_rows(holdings=[{"subject": "another", "contact": CONTACT}])):
        with pytest.raises(AssertionError, match="duplicate"):
            assert_unchanged(after, snapshot(changed))

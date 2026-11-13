"""The protected round trip's fault injector: the front withholds the 2xx
answer to one request (a signer's prepare, an app's owner-act delivery)."""

import base64
import hashlib
import json

import pytest
from protected_round_trip import (
    AnswerDrop,
    Holding,
    SignedAct,
    assert_one_effect,
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
    assert act == SignedAct(nonce="n0nce", sha256=hashlib.sha256(SIGNING).hexdigest(), act="human-role.revoke")


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
ACT_SIGNED = SignedAct(nonce="n0nce", sha256=H, act="human-role.revoke")


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
    snapshot = receiver_snapshot(query, HOLDING, "n0nce")
    assert snapshot["holding"] == {"subject": "s", "ended": False} and "holdings" not in snapshot
    (select,) = queries
    for literal in ("'lfteam-secrets'", "'4fead199-b779'", "'1'", "'lfteam:lf.test'", "'secrets.owner'",
                    "'did:aw:approver'", "'n0nce'"):
        assert literal in select, literal
    assert "h.ended_in IS NULL AND p.superseded_at IS NULL" in select and "a.commitment = NULL" in select
    assert "BEGIN" not in select and "COMMIT" not in select


def test_a_later_snapshot_reads_the_captured_subject_and_this_acts_rows():
    queries, query = snapshot_of({"holdings": [{"subject": "s"}]})
    receiver_snapshot(query, HOLDING, "n0nce", subject="s", act_sha256="a" * 64)
    (select,) = queries
    assert "p.subject = 's'" in select and "ended_in IS NULL" not in select
    assert f"a.commitment = '{'a' * 64}'" in select


@pytest.mark.parametrize("holdings", [[], [{"subject": "s"}, {"subject": "t"}]])
def test_a_snapshot_finding_no_holding_or_several_is_refused(holdings):
    _, query = snapshot_of({"holdings": holdings})
    with pytest.raises(SystemExit, match="holdings"):
        receiver_snapshot(query, HOLDING, "n0nce")


@pytest.mark.parametrize("value", ["it's", "a b", "x;DROP", ""])
def test_a_value_that_is_not_a_plain_identifier_is_never_quoted_into_the_query(value):
    _, query = snapshot_of({"holdings": [{"subject": "s"}]})
    with pytest.raises(SystemExit, match="receiver snapshot"):
        receiver_snapshot(query, HOLDING, value)


def test_the_snapshot_runs_read_only_in_one_session():
    args = read_only_psql("secrets", "SELECT 1")
    assert args[:5] == ["psql", "-U", "postgres", "-d", "secrets"] and "-q" in args and "-At" in args
    commands = [args[i + 1] for i, arg in enumerate(args) if arg == "-c"]
    assert commands == ["BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY", "SELECT 1", "COMMIT"]

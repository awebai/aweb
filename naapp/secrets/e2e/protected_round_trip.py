"""The protected round trip, one body for every place it runs.

First the refusals, while the approver's holding exists: no user
verification and a cancelled LOGIN sign nothing, and a changed act is refused.
Then one human-role.revoke goes through the independent protected server
(aweb.protected_signing.host, HOST.md). Its prepare answer is lost, so aw
keeps the pending operation and its request. Resumed, the approving human logs
in on the console page in a fresh Chromium tab with a passkey and approves the
exact act with a separate user verification; the server signs it once with
the team controller key only it holds; aw delivers it to the app, which
applies it, and the app's answer is withheld. The exact replay of the same
signed act is answered applied earlier. The app's own records show one effect.

The body runs in the secrets e2e lane (tests/test_e2e_protected_revoke.py)
and in the team deployment journey (scripts/e2e/team_deployment_journey.py).
Each supplies a Site: where its machines and files are and how its signer is
configured, provisioned, started and reached. Provisioning follows HOST.md
through B3's own enrolment APIs; nothing inserts a credential, session or
success row.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
import secrets
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pexpect
from awid.did import did_key_from_signing_key
from awid.signing import load_signing_key_pem


def docker(*args: str, timeout: int = 120, input: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], text=True, capture_output=True, timeout=timeout, input=input, check=False)



# AWID's did_key limit (awid/ratelimit.py _BUCKET_DEFAULTS): 60 reads a minute
# per client address, counted in a fixed window keyed by its start.
DID_KEY_LIMIT, DID_KEY_WINDOW = 60, 60
# The least of a window a throttle leg uses: a shorter remainder becomes a
# Retry-After the SDK's own 5 s budget absorbs, and nothing reaches aw.
LEAST_THROTTLED_SECONDS = 20


def did_key_window(now: float, client_ip: str) -> dict:
    """The real limiter's key for client_ip's did_key window at now, as
    RedisFixedWindowRateLimiter writes it (key, limit, its EXPIRE), and how long
    to wait first so that at least LEAST_THROTTLED_SECONDS of it remain."""
    remaining = DID_KEY_WINDOW - now % DID_KEY_WINDOW
    wait = remaining if remaining < LEAST_THROTTLED_SECONDS else 0.0
    window_id = int((now + wait) // DID_KEY_WINDOW)
    return {"key": f"aweb:rl:did_key:{client_ip}:{window_id}", "limit": DID_KEY_LIMIT, "ttl": DID_KEY_WINDOW + 2,
            "wait": wait, "remaining": remaining if not wait else float(DID_KEY_WINDOW)}


def changed_act(record: dict, role: str) -> dict:
    """aw's saved request with only its act's role changed: a validly encoded
    intent under the same operation id."""
    body = json.loads(base64.b64decode(record["body"]))
    body["subject"]["role"] = role
    encoded = base64.b64encode(json.dumps(body, separators=(",", ":"), sort_keys=True).encode()).decode()
    return {**record, "body": encoded}


def first_json(text: str):
    """The first JSON value in a command's output; Docker may print hints after it."""
    return json.JSONDecoder().raw_decode(text[text.index("{"):])[0]


def aw(container: str, *args: str, env: dict[str, str] | None = None) -> dict:
    """Run aw --json in a machine, without a terminal, and return its JSON."""
    extra = [f"--env={k}={v}" for k, v in (env or {}).items()]
    result = docker("exec", *extra, container, "aw", "--json", *args, timeout=300)
    assert result.returncode == 0, f"aw {' '.join(args)}\n{result.stdout}\n{result.stderr}"
    return first_json(result.stdout)


def aw_refused(container: str, *args: str, env: dict[str, str] | None = None) -> str:
    """Run aw --json expecting a refusal; return its error code."""
    extra = [f"--env={k}={v}" for k, v in (env or {}).items()]
    result = docker("exec", *extra, container, "aw", "--json", *args, timeout=300)
    assert result.returncode != 0, result.stdout
    return first_json(result.stdout)["error"]["code"]


def await_awid_txt(machine: str, domain: str, controller_did: str) -> None:
    """Wait, bounded, until the machine's resolver sees the published
    controller: the zone is reloaded once a second, so a lookup made at once
    can still return the previous record."""
    for _ in range(30):
        answer = docker("exec", machine, "nslookup", "-type=txt", f"_awid.{domain}")
        if controller_did in answer.stdout:
            return
        time.sleep(0.5)
    raise AssertionError(f"_awid.{domain} never named {controller_did}")


class Holder:
    """The holder's machine: aw with a human key in its own Secret Service."""

    def __init__(self, container: str, domain: str) -> None:
        self.container, self.domain = container, domain
        # A disposable passphrase, generated now and never printed or stored.
        self.passphrase = secrets.token_urlsafe(24)
        # The session bus and the keyring's files and sockets live on the
        # container's own filesystem: on the runtime bind mount gnome-keyring
        # leaves the login collection locked, and once it drops its
        # capabilities it cannot write a home the host user owns.
        # aw reaches the keyring only over this bus.
        self.bus = "unix:path=/tmp/holder-session.bus"
        keyring = (
            "XDG_RUNTIME_DIR=/tmp/holder-runtime XDG_DATA_HOME=/tmp/holder-keyring "
            "DBUS_SESSION_BUS_ADDRESS=" + self.bus
        )
        # -i: without it docker exec attaches no stdin and the unlock reads no
        # password. The other daemons get /dev/null, so only the unlock reads it.
        started = docker(
            "exec", "-i", container, "sh", "-c",
            "umask 077 && mkdir -p /tmp/holder-keyring /tmp/holder-runtime "
            "&& dbus-daemon --session --fork --address=" + self.bus + " </dev/null "
            "&& " + keyring + " gnome-keyring-daemon --unlock --components=secrets "
            "&& " + keyring + " gnome-keyring-daemon --start --components=secrets </dev/null",
            input=secrets.token_urlsafe(24),
        )
        assert started.returncode == 0, started.stdout + started.stderr

    def act(self, principal: str, *args: str) -> pexpect.spawn:
        """aw as the holder for a command that a holder-signed start begins.

        This is the one place that chooses how the holder authenticates. Today
        it is the existing --human participation (the human key in this
        machine's Secret Service, unlocked at the terminal). The protected
        profile (package 1 rule (b)) replaces only this method: a restricted
        requester credential, a B3 UV login at the protected service, and the
        server's holder-signed start. The H acceptance (acxy.9/11) runs there.
        """
        return self.spawn("--human", principal, "--human-domain", self.domain, *args)

    def spawn(self, *args: str) -> pexpect.spawn:
        """aw on the holder's terminal: docker exec -it gives it a real PTY."""
        return pexpect.spawn(
            "docker",
            ["exec", "-it", f"--env=DBUS_SESSION_BUS_ADDRESS={self.bus}", self.container, "aw", *args],
            encoding="utf-8", timeout=180, echo=False,
        )

    def answer_passphrases(self, child: pexpect.spawn, *, until: str | None = None) -> str:
        """Type the passphrase at each prompt, never logging it; return the output."""
        seen = []
        patterns = [r"Choose a passphrase[^\r\n]*: ", r"Type the passphrase again: ", r"Passphrase for that human key: "]
        if until:
            patterns.append(until)
        patterns.append(pexpect.EOF)
        while True:
            found = child.expect(patterns)
            seen.append(child.before)
            if child.match is pexpect.EOF or (until and found == len(patterns) - 2):
                if until and found == len(patterns) - 2:
                    seen.append(child.match.group(0))
                return "".join(seen)
            child.sendline(self.passphrase)


# The hook bindings a team deployment activates before any owner act: the
# audit-critical pairs that Secrets' governance acts and secret use need, and
# Logs' own governance production, which its reader designation needs. The
# other bindings the manifests declare (Logs' post-command,
# post-manifest-command and post-mutation registrations) have no producer in
# this bundle and stay pending.
REQUIRED_HOOK_BINDINGS = (
    ("secrets", "production", "post-governance-hook"),
    ("secrets", "production", "post-secret-use-hook"),
    ("logs", "registration", "post-governance-hook"),
    ("logs", "registration", "post-secret-use-hook"),
    ("logs", "production", "post-governance-hook"),
)
# The wait past the latest active_from: the producers allow five seconds of
# skew between their clock and the database's that set active_from.
HOOK_READINESS_MARGIN = datetime.timedelta(seconds=10)
# The longest the journey waits for the bindings to come into effect: the
# server's sixty seconds after activation, plus the margin, with room.
HOOK_READINESS_DEADLINE = datetime.timedelta(minutes=3)


# What names a binding: the app's installation, generation and manifest, and
# the binding's kind and hook.
HOOK_BINDING_IDENTITY = ("app_id", "installation_id", "generation", "digest", "kind", "hook")


def select_hook_bindings(listed: dict[str, list[dict]]) -> dict[tuple[str, str, str], dict]:
    """The listed row of each required binding, from each app's listing, named
    by its kind and hook. A required binding listed none or several times is
    refused, and so is an app whose rows are not one installation, generation
    and manifest."""
    for app, rows in listed.items():
        installs = {(r["installation_id"], r["generation"], r["digest"]) for r in rows}
        if len(installs) != 1:
            raise SystemExit(f"FAILED: {app}'s hook bindings are not one installation, generation and manifest: "
                             f"{sorted(map(str, installs))}")
    selected = {}
    for app, kind, hook in REQUIRED_HOOK_BINDINGS:
        matches = [b for b in listed.get(app, []) if (b["kind"], b["hook"]) == (kind, hook)]
        if len(matches) != 1:
            raise SystemExit(f"FAILED: {app} lists {len(matches)} {kind} bindings for {hook}, not one")
        selected[(app, kind, hook)] = matches[0]
    return selected


def hooks_ready_at(listed: list[dict], selected: list[dict],
                   margin: datetime.timedelta = HOOK_READINESS_MARGIN) -> datetime.datetime:
    """When the selected bindings are in effect: the latest of their
    active_from, plus the margin. A selected binding that is not active, has
    no active_from, or is no longer the installation, generation, manifest,
    kind and hook selected, is refused."""
    by_id = {b["binding_id"]: b for b in listed}
    starts = []
    for chosen in selected:
        binding_id = chosen["binding_id"]
        binding = by_id.get(binding_id)
        if binding is None or binding.get("state") != "active" or not binding.get("active_from"):
            raise SystemExit(f"FAILED: hook binding {binding_id} is not active with an active_from: {binding}")
        if any(binding.get(field) != chosen[field] for field in HOOK_BINDING_IDENTITY):
            raise SystemExit(f"FAILED: hook binding {binding_id} is no longer the one selected: {binding}")
        starts.append(datetime.datetime.fromisoformat(binding["active_from"].replace("Z", "+00:00")))
    return max(starts) + margin


def designate_command(app_id: str, role: str, principal: str, credential: str, contact: str) -> list[str]:
    """The owner's designation of a holding of an app role. A role that
    declares a notice contact, as secrets.owner does, takes the holder's."""
    return ["aw", "app", "role", "designate", app_id, "--role", role, "--principal", principal,
            "--credential", credential, "--notice-contact", contact, "--yes"]


# The prefix of the bytes a team's controller key signs for an owner act
# (naapp-lib hooks/owner_act.py PREFIX; awid OwnerActPrefix).
OWNER_ACT_PREFIX = b"aweb.owner-act/1\n"


@dataclass(frozen=True)
class SignedAct:
    """The act a committed operation's signature covers, named by its nonce
    and by H, the SHA-256 of the exact signing bytes delivered to the app."""

    nonce: str
    sha256: str
    act: str
    # Until when the app accepts it: a later delivery is refused signed_act_invalid.
    expires_at: str


def owner_act_document(signing: bytes) -> dict:
    """The act exact signing bytes carry: the owner-act prefix, then its
    canonical JSON."""
    if not signing.startswith(OWNER_ACT_PREFIX):
        raise SystemExit("FAILED: the signing bytes are not an owner act's")
    return json.loads(signing[len(OWNER_ACT_PREFIX):])


def signed_act(signing: str) -> SignedAct:
    """The act in a committed receipt's result.signing: padded standard base64
    with no line break, of the owner-act prefix and the act's canonical JSON."""
    if "\n" in signing or "\r" in signing:
        raise SystemExit("FAILED: the signing bytes have a line break")
    try:
        decoded = base64.b64decode(signing, validate=True)
    except ValueError as error:
        raise SystemExit(f"FAILED: the signing bytes are not standard base64: {error}") from None
    act = owner_act_document(decoded)
    return SignedAct(nonce=act["nonce"], sha256=hashlib.sha256(decoded).hexdigest(), act=act["act"],
                     expires_at=act["expires_at"])


def assert_one_effect(baseline: dict, first: dict, replay: dict, act: SignedAct) -> None:
    """The app's own records show that the first delivery of `act` took
    exactly one effect, and that its replay took none.

    Each snapshot holds the scoped role assignments, the holding (ended, its
    B3 subject, superseded, usable keys), the configuration revision, the
    counts of owner-act nonce rows and narrowing-authority rows for the
    installation, and the rows for this act's nonce and H."""
    assert baseline["assignments"] == 1 and not baseline["holding"]["ended"], f"baseline: not before the effect {baseline}"
    assert not baseline["nonce_rows"] and not baseline["authority_rows"], f"baseline: this act already applied {baseline}"
    expected_rows = ([{"nonce": act.nonce, "act_sha256": act.sha256}], 1)
    assert first["assignments"] == 0, f"first application: still assigned {first}"
    holding = first["holding"]
    assert holding["ended"] and holding["superseded"] and holding["usable_keys"] == 0, f"first application: {holding}"
    assert holding["subject"] == baseline["holding"]["subject"], f"first application: another holder {holding}"
    assert first["revision"] == baseline["revision"] + 1, f"first application: revision {first['revision']}"
    assert first["nonces"] == baseline["nonces"] + 1, f"first application: nonce rows {first['nonces']}"
    assert (first["nonce_rows"], len(first["nonce_rows"])) == expected_rows, f"first application: {first['nonce_rows']}"
    assert first["authorities"] == baseline["authorities"] + 1, f"first application: authorities {first['authorities']}"
    rows = first["authority_rows"]
    assert len(rows) == 1, f"first application: authority rows {rows}"
    row = rows[0]
    assert (row["subject"], row["authority"], row["commitment"], row["signing_sha256"]) == (
        holding["subject"], "owner_act", act.sha256, act.sha256), f"first application: {row}"
    assert row["event_id"] and row["act"] in (None, "role.revoked") and row["event_act_sha256"] in (None, act.sha256), (
        f"first application: governance event {row}")
    # The replay: every record as the first delivery left it.
    for key in ("assignments", "holding", "revision", "nonces", "nonce_rows", "authorities"):
        assert replay[key] == first[key], f"replay: {key} changed {first[key]} -> {replay[key]}"
    assert [(r["event_id"], r["commitment"]) for r in replay["authority_rows"]] == [
        (r["event_id"], r["commitment"]) for r in rows], f"replay: authority rows {replay['authority_rows']}"


@dataclass(frozen=True)
class Holding:
    """What names one holding at the app: its installation and generation, the
    team, the role and the principal."""

    app_id: str
    installation_id: str
    generation: int
    team_id: str
    role: str
    principal: str


def read_only_psql(user: str, database: str, select: str) -> list[str]:
    """The psql arguments that run one SELECT, as `user`, in a repeatable-read,
    read-only transaction and print only its rows: separate commands in one
    session."""
    return ["psql", "-U", user, "-d", database, "-At", "-q", "-v", "ON_ERROR_STOP=1",
            "-c", "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY", "-c", select, "-c", "COMMIT"]


SNAPSHOT_LITERAL = re.compile(r"[A-Za-z0-9:._@/+=-]+")


def sql_literal(value: str | int) -> str:
    text = str(value)
    if not SNAPSHOT_LITERAL.fullmatch(text):
        raise SystemExit(f"FAILED: {text!r} is not a value the receiver snapshot quotes")
    return f"'{text}'"


SQL_SCHEMA = re.compile(r"[a-z_][a-z0-9_]*")


def sql_schema(name: str) -> str:
    if not SQL_SCHEMA.fullmatch(name):
        raise SystemExit(f"FAILED: {name!r} is not a schema the receiver snapshot names")
    return name


def receiver_snapshot(query: Callable[[str], str], holding: Holding, nonce: str, subject: str | None = None,
                      act_sha256: str | None = None, *, schema: str) -> dict:
    """The app's own records of one holding, read in one repeatable-read,
    read-only transaction: the scoped role assignments; the holding (its B3
    subject, whether it ended, whether that subject is superseded, its usable
    passkeys), the current one when `subject` is None, else that subject's;
    the configuration revision; the installation's owner-act nonce rows and
    narrowing-authority rows, counted; and the rows for `nonce` and, once the
    act is signed, for `act_sha256`, all in the app's `schema`. `query` runs
    one SELECT against the app's database, as read_only_psql wraps it, and
    returns its one output line."""
    s = sql_schema(schema)
    team, role, principal = sql_literal(holding.team_id), sql_literal(holding.role), sql_literal(holding.principal)
    installation, app = sql_literal(holding.installation_id), sql_literal(holding.app_id)
    generation = sql_literal(holding.generation)
    which = ("h.ended_in IS NULL AND p.superseded_at IS NULL" if subject is None
             else f"p.subject = {sql_literal(subject)}")
    commitment = sql_literal(act_sha256) if act_sha256 else "NULL"
    text = query(
        "SELECT json_build_object("
        f"'assignments', (SELECT count(*) FROM {s}.role_assignments WHERE team_id = {team} AND role = {role}"
        f" AND principal_did = {principal}),"
        "'holdings', (SELECT coalesce(json_agg(json_build_object('subject', p.subject,"
        " 'ended', h.ended_in IS NOT NULL, 'superseded', p.superseded_at IS NOT NULL,"
        f" 'usable_keys', (SELECT count(*) FROM {s}.passkey_credentials k"
        "  WHERE k.subject = p.subject AND k.revoked_at IS NULL))), '[]'::json)"
        f" FROM {s}.role_holdings h JOIN {s}.passkey_approvers p ON p.scope = h.b3_scope"
        f" WHERE h.installation_id = {installation} AND h.team_id = {team} AND h.role = {role}"
        f" AND h.principal_did = {principal} AND {which}),"
        f"'revision', coalesce((SELECT revision FROM {s}.config_revisions"
        f" WHERE installation_id = {installation} AND team_id = {team}), 0),"
        f"'nonces', (SELECT count(*) FROM {s}.owner_act_nonces WHERE scope = {app} AND team_id = {team}),"
        "'nonce_rows', (SELECT coalesce(json_agg(json_build_object('nonce', nonce, 'act_sha256', act_sha256)),"
        f" '[]'::json) FROM {s}.owner_act_nonces WHERE scope = {app} AND team_id = {team}"
        f" AND nonce = {sql_literal(nonce)}),"
        f"'authorities', (SELECT count(*) FROM {s}.credential_narrowing_authority"
        f" WHERE app_id = {app} AND team_id = {team} AND installation_id = {installation}"
        f" AND generation = {generation}::bigint AND authority = 'owner_act'),"
        "'authority_rows', (SELECT coalesce(json_agg(json_build_object('event_id', a.event_id,"
        " 'subject', a.subject, 'authority', a.authority, 'commitment', a.commitment,"
        " 'signing_sha256', encode(sha256(a.signing), 'hex'), 'kind', e.kind,"
        " 'act', CASE WHEN e.payload IS NOT NULL THEN"
        "  (convert_from(e.payload, 'UTF8')::jsonb)->'payload'->>'act' END,"
        " 'event_act_sha256', CASE WHEN e.payload IS NOT NULL THEN"
        "  (convert_from(e.payload, 'UTF8')::jsonb)->'payload'->>'owner_act_sha256' END)), '[]'::json)"
        f" FROM {s}.credential_narrowing_authority a LEFT JOIN {s}.outbox_events e USING (event_id)"
        f" WHERE a.app_id = {app} AND a.team_id = {team} AND a.installation_id = {installation}"
        f" AND a.generation = {generation}::bigint AND a.authority = 'owner_act' AND a.commitment = {commitment})"
        ")")
    snapshot = json.loads(text)
    holdings = snapshot.pop("holdings")
    if len(holdings) != 1:
        raise SystemExit(f"FAILED: the app holds {len(holdings)} holdings for {holding} (subject {subject}), not one")
    snapshot["holding"] = holdings[0]
    return snapshot


# --- a designation's effect, which the owner signs locally ------------------

HUMAN_CREDENTIAL_PREFIX = b"aweb.human-credential/1\n"


def credential_sha256(credential: dict) -> str:
    """A human credential's credential_sha256 (docs/owner-act-delivery.md, "The
    credential"): the SHA-256 of its prefix and the canonical JSON of its id,
    public key and relying party."""
    canonical = json.dumps({field: credential[field] for field in ("credential_id", "public_key", "rp_id")},
                           separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(HUMAN_CREDENTIAL_PREFIX + canonical.encode()).hexdigest()


@dataclass(frozen=True)
class Designation:
    """What the owner designates: the holding, at the app's console origin
    (the act's audience), for the exported credential, with the notice
    contact the owner gives."""

    holding: Holding
    audience: str
    credential_sha256: str
    contact: str


def designation_snapshot(query: Callable[[str], str], holding: Holding, *, schema: str) -> dict:
    """The app's own records of one designation, read in one repeatable-read,
    read-only transaction in the app's `schema`: the scoped role assignments;
    the current holding (its B3 subject and notice contact); the configuration
    revision; the counts of owner-act nonce rows for the app and team and of
    credential authorizations for the holding; each such authorization, with
    the act its retained signing bytes carry and their digest; and the nonce
    rows whose act is one of those authorizations' commitments. The signing
    bytes themselves are not kept."""
    s = sql_schema(schema)
    team, role, principal = sql_literal(holding.team_id), sql_literal(holding.role), sql_literal(holding.principal)
    installation, app = sql_literal(holding.installation_id), sql_literal(holding.app_id)
    generation = sql_literal(holding.generation)
    authorized = (f" FROM {s}.credential_authorizations WHERE app_id = {app} AND team_id = {team}"
                  f" AND installation_id = {installation} AND generation = {generation}::bigint AND role = {role}"
                  f" AND principal = {principal}")
    text = query(
        "SELECT json_build_object("
        f"'assignments', (SELECT count(*) FROM {s}.role_assignments WHERE team_id = {team} AND role = {role}"
        f" AND principal_did = {principal}),"
        "'holdings', (SELECT coalesce(json_agg(json_build_object('subject', p.subject, 'contact', p.contact)),"
        f" '[]'::json) FROM {s}.role_holdings h JOIN {s}.passkey_approvers p ON p.scope = h.b3_scope"
        f" WHERE h.installation_id = {installation} AND h.team_id = {team} AND h.role = {role}"
        f" AND h.principal_did = {principal} AND h.ended_in IS NULL AND p.superseded_at IS NULL),"
        f"'revision', coalesce((SELECT revision FROM {s}.config_revisions"
        f" WHERE installation_id = {installation} AND team_id = {team}), 0),"
        f"'nonces', (SELECT count(*) FROM {s}.owner_act_nonces WHERE scope = {app} AND team_id = {team}),"
        f"'authorizations', (SELECT count(*){authorized}),"
        "'authorization_rows', (SELECT coalesce(json_agg(json_build_object('subject', subject,"
        " 'authority', authority, 'commitment', commitment, 'signing_sha256', encode(sha256(signing), 'hex'),"
        " 'signing_hex', encode(signing, 'hex'), 'principal', principal,"
        " 'notice_contact_sha256', notice_contact_sha256, 'credential_sha256', credential_sha256)), '[]'::json)"
        f"{authorized}),"
        "'nonce_rows', (SELECT coalesce(json_agg(json_build_object('nonce', nonce, 'act_sha256', act_sha256)),"
        f" '[]'::json) FROM {s}.owner_act_nonces WHERE scope = {app} AND team_id = {team}"
        f" AND act_sha256 IN (SELECT commitment{authorized}))"
        ")")
    snapshot = json.loads(text)
    for row in snapshot["authorization_rows"]:
        signing = row.pop("signing_hex")
        row["document"] = owner_act_document(bytes.fromhex(signing)) if signing else None
    return snapshot


def assert_designated(baseline: dict, after: dict, designation: Designation) -> None:
    """The app's own records show that the owner's one designation took
    effect: the holding exists with the signed contact, and its one
    authorization is the owner's act, bound to the act the owner meant (its
    kind, team, audience, app, installation, role, principal, credential and
    contact) and to exactly one nonce row with that act's nonce and H."""
    holding = designation.holding
    assert baseline["assignments"] == 0 and not baseline["holdings"], f"baseline: already held {baseline}"
    assert not baseline["authorization_rows"] and not baseline["nonce_rows"], f"baseline: already designated {baseline}"
    contact_sha256 = hashlib.sha256(designation.contact.encode()).hexdigest()
    assert after["assignments"] == 1, f"designation: assignments {after['assignments']}"
    assert len(after["holdings"]) == 1, f"designation: holdings {after['holdings']}"
    (held,) = after["holdings"]
    assert held["contact"] == designation.contact, f"designation: contact {held}"
    for key in ("revision", "nonces", "authorizations"):
        assert after[key] == baseline[key] + 1, f"designation: {key} {baseline[key]} -> {after[key]}"
    rows = after["authorization_rows"]
    assert len(rows) == 1 and rows[0]["subject"] == held["subject"], f"designation: authorizations {rows}"
    (row,) = rows
    assert (row["authority"], row["principal"], row["notice_contact_sha256"], row["credential_sha256"]) == (
        "owner_act", holding.principal, contact_sha256, designation.credential_sha256), f"designation: {row}"
    assert row["commitment"] == row["signing_sha256"], f"designation: the commitment is not H {row}"
    document = row["document"] or {}
    expected = {"act": "human-role.designate", "team_id": holding.team_id, "aud": designation.audience,
                "subject": {"app_id": holding.app_id, "installation_id": holding.installation_id,
                            "role": holding.role, "principal": holding.principal,
                            "credential_sha256": designation.credential_sha256,
                            "notice_contact_sha256": contact_sha256}}
    signed = {key: document.get(key) for key in expected}
    assert signed == expected, f"designation: the signed act is not the one meant {signed}"
    assert after["nonce_rows"] == [{"nonce": document["nonce"], "act_sha256": row["commitment"]}], (
        f"designation: nonce rows {after['nonce_rows']}")


def assert_unchanged(after: dict, duplicate: dict) -> None:
    """A refused duplicate designation left every scoped record as the
    designation left it."""
    for key in after:
        assert duplicate[key] == after[key], f"duplicate: {key} changed {after[key]} -> {duplicate[key]}"


class AnswerDrop:
    """The front withholds the answer to one request: while it is in effect,
    every 2xx answer to `method` `path` on `host` is aborted, so the caller
    sees its connection lost after the upstream has answered.

    Entering it reads the front's Caddyfile as it is rendered then, and
    refuses, changing nothing, unless the file holds exactly one site for
    `host`; leaving it, also on an exception, puts back exactly the text it
    replaced. Each change is reloaded."""

    def __init__(self, rendered: Path, host: str, method: str, path: str, upstream: str,
                 reload: Callable[[], None]):
        self.rendered, self.host, self.method, self.path = rendered, host, method, path
        self.upstream, self.reload = upstream, reload
        self.replaced: str | None = None

    def __enter__(self) -> AnswerDrop:
        if self.replaced is not None:
            raise SystemExit(f"FAILED: the drop for {self.method} {self.path} on {self.host} is already in effect")
        current = self.rendered.read_text()
        site = f"{self.host}:443 {{\n"
        if current.count(site) != 1:
            raise SystemExit(f"FAILED: the front holds {current.count(site)} sites for {self.host}, not one;"
                             f" the answers to {self.method} {self.path} cannot be dropped")
        self.rendered.write_text(current.replace(
            site,
            f"{site}  @dropped {{\n    method {self.method}\n    path {self.path}\n  }}\n"
            f"  reverse_proxy @dropped {self.upstream} {{\n    @answered status 2xx\n"
            "    handle_response @answered {\n      abort\n    }\n  }\n", 1))
        self.replaced = current
        self.reload()
        return self

    def __exit__(self, *_: object) -> None:
        if self.replaced is None:
            return
        self.rendered.write_text(self.replaced)
        self.replaced = None
        self.reload()


@dataclass
class Site:
    """Where one round trip runs. ``runtime`` is the host directory every
    machine and the Chromium driver mount at ``mounted``; a machine's HOME is
    ``mounted``/its name."""

    runtime: Path
    mounted: str
    domain: str
    team: str
    registry: str
    aweb: str
    signer: str
    human: str
    service_id: str
    # The installed Secrets and Logs apps' ids, and the schema Secrets keeps
    # its records in.
    app_id: str
    logs_app_id: str
    secrets_schema: str
    role: str
    contact: str
    # The captured notification transport's API, as a machine reaches it.
    mail_api: str
    # The operator profile, as aw in the holder's machine reads it.
    profile_in_machine: str
    publish_controller: Callable[[str], None]
    # The signer's ordinary member key (aw's PEM file), stored where only it reads.
    store_member: Callable[[str], None]
    # The operator profile and scope, and the process configuration.
    configure_signer: Callable[[dict, dict], None]
    # The team owner's existing controller PEM into the signer's private
    # custody, by the package's install-controller command.
    install_controller: Callable[[Path], None]
    # python -m aweb.protected_signing.operator in the signer's container, as
    # its uid with its own settings; returns its JSON.
    operator: Callable[..., dict]
    start_signer: Callable[[], None]
    # What the signer holds for one operation, read from its database
    # (e2e/protected/evidence.py): signed, refusal_code, expires_at,
    # frozen_nonce, and for a signed one the act's act_sha256 and nonce.
    signer_evidence: Callable[[str], dict]
    # How many operations the signer has signed.
    signatures: Callable[[], int]
    # The signer's own access log so far, as uvicorn writes it.
    signer_access_log: Callable[[], str]
    # The approving human's Chromium in a machine's network namespace.
    chromium: Callable[..., dict]
    # The front withholding the signer's answers to POST /protected-operations.
    drop_prepare_answers: Callable[[], AnswerDrop]
    # The front withholding the app's answers to POST /.well-known/aweb-owner-act
    # on the app's console host.
    drop_owner_act_answers: Callable[[], AnswerDrop]
    # One SELECT against the app's database, read only (read_only_psql).
    secrets_query: Callable[[str], str]
    # The app's own access log so far.
    app_log: Callable[[], str]

    @property
    def team_id(self) -> str:
        return f"{self.team}:{self.domain}"

    @property
    def rp_id(self) -> str:
        return self.human.removeprefix("https://")


@dataclass(frozen=True)
class Founded:
    """The namespace, its root human (the approver) and the team, and the
    requester: a root-parented agent identity of the team, connected to aweb."""

    controller_did: str
    approver: str
    approver_did_key: str
    requester: str
    requester_did_key: str


def found_team(site: Site, holder: Holder) -> Founded:
    """The namespace, its root human H and the team, on H's machine. The same
    machine holds the namespace controller, so aw creates the root-parented
    requester there, beside H's human key; connect_requester connects it to
    aweb once aweb serves the team."""
    machine = holder.container
    prepared = aw(machine, "id", "namespace", "prepare-controller", "--domain", site.domain, "--registry", site.registry)
    site.publish_controller(prepared["controller_did"])
    await_awid_txt(machine, site.domain, prepared["controller_did"])
    child = holder.spawn("--json", "id", "human", "init", "--domain", site.domain, "--as-root")
    output = holder.answer_passphrases(child)
    child.close()
    assert child.exitstatus == 0, output
    human = first_json(output)
    approver = human["id"]
    aw(machine, "id", "team", "create", "--name", site.team, "--namespace", site.domain, "--registry", site.registry)
    created = aw(machine, "id", "create", "--name", "owner", "--domain", site.domain, "--root-parent",
                 "--registry", site.registry)
    invite = aw(machine, "id", "team", "invite", "--team", site.team, "--namespace", site.domain, "--member-global")
    aw(machine, "id", "team", "accept-invite", invite["token"], "--name", "owner", "--global")
    return Founded(prepared["controller_did"], approver, human["did_key"], created["did_aw"], created["did_key"])


def connect_requester(site: Site, holder: Holder) -> None:
    """The requester, a member of the team, connects to the team's aweb."""
    aw(holder.container, "init", "--url", site.aweb, "--name", "owner", "--do-not-touch-agents-md")


def publish_team_server(machine: str, team: str, domain: str, aweb: str, registry: str) -> dict:
    """The owner, on the machine holding the team's key, publishes the team's
    coordination server at the registry, signed by that key; installed apps
    read it there to reach aweb."""
    aw(machine, "id", "team", "set-server", "--team", team, "--namespace", domain, "--url", aweb,
       "--registry", registry)
    published = aw(machine, "id", "team", "show-server", "--team", team, "--namespace", domain,
                   "--registry", registry)
    assert published.get("server_url", "").rstrip("/") == aweb, published
    return published


def install_app(machine: str, api_origin: str) -> None:
    """The installation owner installs one app from its API origin."""
    installed = aw(machine, "plugin", "install", api_origin)
    if not installed.get("approved"):
        raise SystemExit(f"BOUNDARY: {api_origin} was not installed: {json.dumps(installed)}")


def hook_app_ids(site: Site) -> dict[str, str]:
    return {"secrets": site.app_id, "logs": site.logs_app_id}


def activate_hooks(machine: str, apps: dict[str, str]) -> dict:
    """The owner activates the required hook bindings with its own
    controller key, one supported owner act each, then waits until they are
    in effect: every selected binding active, as the installation,
    generation and manifest selected, and the latest active_from plus a
    margin past. Binding readiness, not proof of delivery. The other
    bindings stay pending. `apps` names each installed app's id by its
    name in REQUIRED_HOOK_BINDINGS."""

    def bindings() -> dict[str, list[dict]]:
        return {app: aw(machine, "hooks", "bindings", app_id)["bindings"] for app, app_id in apps.items()}

    selected = select_hook_bindings(bindings())
    for (app, _, _), row in selected.items():
        activated = docker("exec", machine, "aw", "hooks", "activate", apps[app], row["binding_id"], "--yes",
                           timeout=300)
        assert activated.returncode == 0, activated.stdout + activated.stderr
    after = [row for rows in bindings().values() for row in rows]
    ready = hooks_ready_at(after, list(selected.values()))
    wait = (ready - datetime.datetime.now(datetime.UTC)).total_seconds()
    if wait > HOOK_READINESS_DEADLINE.total_seconds():
        raise SystemExit(f"FAILED: the hook bindings are in effect only at {ready.isoformat()}, past the deadline")
    if wait > 0:
        time.sleep(wait)
    chosen = {row["binding_id"] for row in selected.values()}
    pending = sorted(f"{row['app_id']}/{row['kind']}/{row['hook']}" for row in after
                     if row["binding_id"] not in chosen)
    assert all(row["state"] == "pending" for row in after if row["binding_id"] not in chosen), after
    active = {f"{app}/{kind}/{hook}": {field: row[field] for field in HOOK_BINDING_IDENTITY + ("binding_id",)}
              for (app, kind, hook), row in selected.items()}
    return {"active": active, "left_pending": pending, "ready_at": ready.isoformat()}


def secrets_holding(site: Site, hooks: dict, principal: str) -> Holding:
    """The principal's holding of the app role, named by the Secrets
    installation and generation whose bindings were activated."""
    binding = hooks["active"]["secrets/production/post-governance-hook"]
    return Holding(app_id=site.app_id, installation_id=binding["installation_id"], generation=binding["generation"],
                   team_id=site.team_id, role=site.role, principal=principal)


def holding_of(site: Site, principal: str) -> tuple[str, str]:
    """The principal's holdings of the app role, and its current notice
    contact, in the app's own tables."""
    schema, role, who = sql_schema(site.secrets_schema), sql_literal(site.role), sql_literal(principal)
    held = site.secrets_query(f"SELECT count(*) FROM {schema}.role_assignments WHERE role = {role}"
                              f" AND principal_did = {who}")
    contact = site.secrets_query(f"SELECT contact FROM {schema}.passkey_approvers WHERE principal = {who}"
                                 " AND superseded_at IS NULL")
    return held, contact


def designate_holding(site: Site, holder: Holder, founded: Founded) -> dict:
    """The approver's holding of the app role the round trip revokes, made
    the supported way while the owner still holds the team's key: the
    owner adds the human to the team; the human, with its own key, fetches
    its certificate, connects to the team's aweb and registers a passkey on
    the app's own human origin in the browser, for the app the owner
    installed on this machine; the owner designates that exact credential,
    once the hook bindings its governance needs are in effect. Checked in
    the app's own tables."""
    machine, human = holder.container, founded.approver
    # --global for this human holder only (services and seats stay --local):
    # aw binds a holder only if its team certificate names its did:aw
    # (verifyHolderEvidence), and a did:aw on a member certificate is a
    # global identity's.
    added = aw(machine, "id", "team", "add-member", "--team", site.team, "--namespace", site.domain,
               "--did", founded.approver_did_key, "--did-aw", human, "--name", "approver", "--global")

    def as_human(*args: str, until: str | None = None) -> tuple[pexpect.spawn, str]:
        child = holder.act(human, *args)
        return child, holder.answer_passphrases(child, until=until)

    for args in (("--json", "id", "team", "fetch-cert", "--namespace", site.domain, "--team", site.team, "--cert-id",
                  added["certificate_id"], "--registry", site.registry),
                 # The human's own connection to the team's aweb: the
                 # requester's does not serve this separate identity.
                 ("--json", "init", "--url", site.aweb, "--human-name", "approver")):
        child, output = as_human(*args)
        child.close()
        assert child.exitstatus == 0, output
    # The app is already installed on this machine: the owner installed it
    # here, in the same aw plugin directory. aw takes no --human install.
    export = f"{site.mounted}/holder/app-export.json"
    child, output = as_human("app", "credential", "register", site.app_id, "--role", site.role, "--out", export,
                             until=r"Open this page to continue: (\S+)")
    linked = re.search(r"Open this page to continue: (\S+)", output)
    if not linked:
        child.close()
        raise SystemExit(f"FAILED: the holder's credential registration showed no page (exit {child.exitstatus}):\n{output}")
    report = site.chromium(machine, "credential", "--url", linked.group(1), "--device",
                           f"{site.mounted}/holder-app-device.json")
    assert report["states"] == ["ready", "navigated"] and report["credentials"] == 1, report
    child.expect(pexpect.EOF)
    rest = child.before
    child.close()
    assert child.exitstatus == 0, rest
    printed = re.search(r"Fingerprint: ([0-9a-f]{4}(?: [0-9a-f]{4}){3})", output + rest)
    assert printed, output + rest
    fingerprint = printed.group(1)
    command = designate_command(site.app_id, site.role, human, export, site.contact)
    # Before the hook bindings are in effect, the act's governance event has
    # no audit target: the app refuses it, and nothing is held.
    early = docker("exec", machine, *command, timeout=300)
    assert early.returncode != 0 and "503 release_context_unavailable" in early.stdout + early.stderr, (
        early.stdout + early.stderr)
    assert holding_of(site, human) == ("0", ""), holding_of(site, human)
    hooks = activate_hooks(machine, hook_app_ids(site))
    # The owner signs only for that exact credential: aw shows its fingerprint.
    designated = docker("exec", machine, *command, timeout=300)
    assert designated.returncode == 0, designated.stdout + designated.stderr
    assert fingerprint in designated.stderr, designated.stderr
    # The holding keeps the notice contact the owner signed, byte for byte.
    held, contact = holding_of(site, human)
    assert held == "1", held
    assert contact == site.contact, contact
    return {"role": site.role, "principal": human, "fingerprint": fingerprint, "contact": contact,
            "refused_before_activation": "503 release_context_unavailable", "hooks": hooks}


def enrolment_link(site: Site, machine: str) -> str:
    """The approver's enrolment link, as the signer delivered it to the
    captured transport."""
    listing = docker("exec", machine, "wget", "-qO-", f"{site.mail_api}/api/v1/messages")
    assert listing.returncode == 0, listing.stderr
    messages = [m for m in json.loads(listing.stdout)["messages"] if any(t["Address"] == site.contact for t in m["To"])]
    assert len(messages) == 1, messages
    message = docker("exec", machine, "wget", "-qO-", f"{site.mail_api}/api/v1/message/{messages[0]['ID']}")
    link = re.search(re.escape(site.human) + r"/enrolment#token=\S+", json.loads(message.stdout)["Text"])
    assert link, message.stdout
    return link.group(0)


def provision_signer(site: Site, holder: Holder, founded: Founded) -> None:
    """Configure the signer, install its controller, bootstrap its first
    approver with the operator command, start it, and enrol the approver's
    passkey on its human origin's own page."""
    machine = holder.container
    # The protected server's ordinary member credential (never the controller):
    # aw creates the key in the member's own identity.
    home = f"{site.mounted}/protected-reader"
    (site.runtime / "protected-reader" / "identity").mkdir(parents=True, mode=0o700)
    requested = first_json(docker("exec", "-e", f"HOME={home}", "-w", f"{home}/identity", machine, "aw", "--json",
                                  "id", "team", "request", "--create-local-key", "--team", site.team_id,
                                  "--name", "protected-reader", timeout=300).stdout)
    added = aw(machine, "id", "team", "add-member", "--team", site.team, "--namespace", site.domain,
               "--did", requested["did_key"], "--name", "protected-reader", "--local")
    assert added["certificate_id"]
    site.store_member((site.runtime / "protected-reader" / "identity" / ".aw" / "signing.key").read_text())

    # The operator profile, its one binding, and the process configuration.
    # The binding names the team controller's public key, read from the
    # owner's existing PEM.
    team_key = site.runtime / "holder" / ".awid" / "team-keys" / site.domain / f"{site.team}.key"
    controller_did = did_key_from_signing_key(load_signing_key_pem(team_key.read_bytes()))
    scope = {"v": 1, "kind": "protected_key", "service_id": site.service_id,
             "authority": {"kind": "team_controller", "id": site.team_id, "domain": site.domain},
             "human": {"id": founded.approver, "domain": site.domain}, "generation": 1}
    profile = {
        "v": 1, "service_id": site.service_id, "request_origin": site.signer, "human_origin": site.human,
        "rp_id": site.rp_id, "registry_origin": site.registry,
        "namespace_authorities": [{"domain": site.domain, "controller_did": founded.controller_did}],
        "bindings": [{"scope": scope, "authority_key_did": controller_did,
                      "policy": {"ref": "aweb.human-assurance/1", "version": 1}}],
    }
    site.configure_signer(profile, scope)

    # Team administration is done: the controller key leaves the holder's
    # machine for the protected server's custody (HOST.md, controller key
    # installation).
    site.install_controller(team_key)
    team_key.unlink()

    # HOST.md, first operator enrollment: the operator's once-only bootstrap
    # mails the approver's enrolment link; on the started host's human origin
    # the shared page registers the passkey through B3, then check.
    site.operator("bootstrap", "--requester", founded.requester, "--contact", site.contact)
    site.start_signer()
    site.chromium(machine, "enrol-page", "--url", enrolment_link(site, machine),
                  "--device", f"{site.mounted}/approver-device.json")
    assert site.operator("check") == {"provisioned": True, "service_id": site.service_id}


def start_revoke(site: Site, machine: str, principal: str) -> tuple[pexpect.spawn, str, str, str]:
    """aw prepares the revoke as the requester; returns the page it names, the
    operation id and the digest it printed."""
    child = pexpect.spawn(
        "docker", ["exec", "-it", machine, "aw", "--json", "app", "role", "revoke", site.app_id, "--role", site.role,
                   "--principal", principal, "--protected-profile", site.profile_in_machine, "--approver", principal],
        encoding="utf-8", timeout=180, echo=False,
    )
    child.expect(r"Operation (\S+)\r?\n\s+digest:\s+([0-9a-f]{64})")
    operation, digest = child.match.group(1), child.match.group(2)
    child.expect(r"Approve it on this page: (\S+)")
    page = child.match.group(1)
    assert page.startswith(site.human + "/handoff/"), page
    return child, page, operation, digest


def finish(child: pexpect.spawn) -> tuple[int, str]:
    child.expect(pexpect.EOF, timeout=240)
    output = child.before
    child.close()
    return child.exitstatus, output


def approve(site: Site, machine: str, page: str, *uv: str) -> dict:
    return site.chromium(machine, "approve", "--url", page, "--device", f"{site.mounted}/approver-device.json", *uv)


ACCESS = re.compile(r'"(GET|POST) (\S+) HTTP/[\d.]+" (\d{3})')


def handoff_requests(site: Site, page: str) -> list[tuple[str, str, int]]:
    """The requests the signer served for one handoff page, in order: from the
    page's own load up to the next page or prepare, so another handoff's
    requests cannot count for this one."""
    handoff = "/handoff/" + page.rsplit("/handoff/", 1)[1]
    served = [(m.group(1), m.group(2), int(m.group(3))) for m in ACCESS.finditer(site.signer_access_log())]
    start = next(i for i, (method, path, _) in enumerate(served) if method == "GET" and path == handoff)
    segment = []
    for method, path, status in served[start + 1:]:
        if (method == "GET" and path.startswith("/handoff/")) or (method == "POST" and path == "/protected-operations"):
            break
        segment.append((method, path, status))
    return segment


def refusals(site: Site, holder: Holder, founded: Founded) -> None:
    """The essential refusals, each with what was and was not signed. None
    signs or applies anything: they run while the holding exists."""
    machine, approver = holder.container, founded.approver
    saved = site.runtime / "holder" / ".config" / "aw" / "governance"

    # No user verification, at the login and then at the approval: nothing
    # is signed, and the operation stays pending with its saved request.
    pending = []
    for phase in ("login", "approve"):
        child, page, operation, _ = start_revoke(site, machine, approver)
        uv = ("--login-without-uv",) if phase == "login" else ("--approve-uv", "no")
        report = approve(site, machine, page, *uv)
        assert "navigated" not in report["states"], report
        if phase == "login":
            # An injected, correctly signed LOGIN assertion without user
            # verification (the driver checks it before sending); the signer
            # refuses it with 401 and the page ends refused, never showing an
            # act ready for approval or asking about one.
            assert report["login_assertion"] == "injected-uv-cleared-signature-verified", report
            assert report["states"] == ["login-required", "refused"], report
            assert not report.get("digest") and not report.get("act"), report
            requests = handoff_requests(site, page)
            assert ("POST", "/login", 401) in requests, requests
            assert not any("/governance/" in path for _, path, _ in requests), requests
        else:
            assert report["states"][-1] == "ready", report
        child.sendintr()
        finish(child)
        assert site.signer_evidence(operation)["signed"] is False
        assert (saved / f"{operation}.json").exists()
        pending.append(operation)

    # A cancelled LOGIN prompt: the browser itself rejects it (no user
    # presence, the options' timeout hint shortened), so no assertion is sent.
    # The page returns to sign-in and shows no act for approval.
    child, page, operation, _ = start_revoke(site, machine, approver)
    report = approve(site, machine, page, "--login-cancel")
    assert report["states"] == ["login-required", "login-required"], report
    # The rejection comes at the shortened timeout, not at once.
    assert report["login_seconds"] >= 0.9, report
    # The page shows this only when navigator.credentials.get rejected with NotAllowedError.
    assert report["status"] == "The passkey prompt was cancelled. You can try again.", report
    requests = handoff_requests(site, page)
    assert ("POST", "/login/options", 200) in requests, requests
    assert not any(path == "/login" or "/governance/" in path for _, path, _ in requests), requests
    child.sendintr()
    finish(child)
    assert site.signer_evidence(operation)["signed"] is False
    assert (saved / f"{operation}.json").exists()

    # A changed act under the same operation id: a validly encoded intent
    # with another role, resent from aw's saved request. The service refuses
    # operation_conflict and signs nothing.
    changed = pending[0]
    record = changed_act(json.loads((saved / f"{changed}.json").read_text()), site.role + "-other")
    (saved / f"{changed}.json").write_text(json.dumps(record))
    refused = docker("exec", machine, "aw", "--json", "app", "role", "resume", changed,
                     "--protected-profile", site.profile_in_machine)
    assert refused.returncode != 0, refused.stdout
    assert first_json(refused.stdout)["error"]["code"] == "operation_conflict", refused.stdout
    assert site.signer_evidence(changed)["signed"] is False


def lost_prepare(site: Site, holder: Holder, founded: Founded) -> str:
    """Prepare loss: the front withholds the signer's answer to the committed
    prepare of a revoke. aw reads the receipt instead of preparing again and
    keeps the request: the operation is pending, unsigned, and has had no
    effect. Returns its id."""
    machine, approver = holder.container, founded.approver
    saved = site.runtime / "holder" / ".config" / "aw" / "governance"
    with site.drop_prepare_answers():
        lost = docker("exec", machine, "aw", "--json", "app", "role", "revoke", site.app_id, "--role", site.role,
                      "--principal", approver, "--protected-profile", site.profile_in_machine, "--approver", approver,
                      timeout=240)
    assert lost.returncode != 0, f"prepare loss: aw did not fail {lost.stdout}"
    assert first_json(lost.stdout)["error"]["code"] == "prepare_unconfirmed", f"prepare loss: {lost.stdout}"
    preparing = re.search(r"Preparing operation (\S+)", lost.stderr)
    assert preparing, f"prepare loss: no operation named {lost.stderr}"
    operation = preparing.group(1)
    assert (saved / f"{operation}.json").exists(), "prepare loss: the request was not saved"
    assert site.signer_evidence(operation)["signed"] is False, "prepare loss: signed before any approval"
    return operation


# The app's answers to the owner-act deliveries, in its own access log.
DELIVERIES = re.compile(r'"POST /\.well-known/aweb-owner-act HTTP/[\d.]+" (\d{3})')


def deliveries(site: Site) -> list[int]:
    return [int(m.group(1)) for m in DELIVERIES.finditer(site.app_log())]


def deliver_once_lost(site: Site, holder: Holder, operation: str, aw_bin: str = "aw",
                      timeout: int = 300) -> dict:
    """Approval and the first application, with its answer lost: aw resumes
    the pending operation from its saved request, the human approves the
    exact act aw printed, the signer signs it once, and aw delivers it to the
    app, which applies it; the front withholds the app's answer, so aw keeps
    the request. Returns when aw printed the page, the printed digest and the
    signed act."""
    machine = holder.container
    saved = site.runtime / "holder" / ".config" / "aw" / "governance"
    answered = deliveries(site)
    with site.drop_owner_act_answers():
        child = pexpect.spawn("docker", ["exec", "-it", machine, aw_bin, "--json", "app", "role", "resume", operation,
                                         "--protected-profile", site.profile_in_machine],
                              encoding="utf-8", timeout=timeout, echo=False)
        started = time.monotonic()
        child.expect(r"Operation (\S+)\r?\n\s+digest:\s+([0-9a-f]{64})")
        printed, digest = child.match.group(1), child.match.group(2)
        child.expect(r"Approve it on this page: (\S+)")
        paged = round(time.monotonic() - started, 1)
        report = approve(site, machine, child.match.group(1))
        status, output = finish(child)
    assert printed == operation, f"approval: aw resumed {printed}, not {operation}"
    assert report["states"] == ["login-required", "ready", "navigated"], f"approval: {report}"
    assert report["digest"] == digest and report["act"] == "human-role.revoke", f"approval: {report}"
    evidence = site.signer_evidence(operation)
    assert evidence["signed"] is True and evidence["refusal_code"] is None, f"approval: {evidence}"
    assert status != 0, f"lost answer: aw settled although the answer was withheld {output}"
    error = first_json(output)["error"]
    # A transport loss carries no app code; an app's own refusal keeps its code.
    assert error["code"] == "owner_act_undelivered", f"lost answer: {error}"
    assert f"aw app role resume {operation}" in error["message"], f"lost answer: {error}"
    assert (saved / f"{operation}.json").exists(), "lost answer: the request was not kept"
    # The app answered the one delivery 200; the front withheld it.
    assert deliveries(site)[len(answered):] == [200], f"first application: the app answered {deliveries(site)}"
    act = SignedAct(nonce=evidence["nonce"], sha256=evidence["act_sha256"], act="human-role.revoke",
                    expires_at=evidence["act_expires_at"])
    return {"paged": paged, "digest": digest, "act": act}


def replay_delivery(site: Site, holder: Holder, operation: str, act: SignedAct, aw_bin: str = "aw") -> dict:
    """Exact replay: aw resumes the same operation, which is already committed,
    and delivers the identical signed act again; the app finds it applied
    earlier and answers 409, so aw settles it as applied earlier and forgets
    the request. Returns aw's report."""
    machine = holder.container
    saved = site.runtime / "holder" / ".config" / "aw" / "governance"
    answered = deliveries(site)
    replayed = docker("exec", machine, aw_bin, "--json", "app", "role", "resume", operation,
                      "--protected-profile", site.profile_in_machine, timeout=300)
    assert replayed.returncode == 0, f"replay: {replayed.stdout}{replayed.stderr}"
    report = first_json(replayed.stdout)
    assert (report["operation_id"], report["state"], report["applied"]) == (operation, "committed", "earlier"), (
        f"replay: {report}")
    assert signed_act(report["result"]["signing"]) == act, "replay: aw delivered other signing bytes"
    assert site.signer_evidence(operation)["act_sha256"] == act.sha256, "replay: the signer's act changed"
    assert not (saved / f"{operation}.json").exists(), "replay: the settled request was kept"
    assert deliveries(site)[len(answered):] == [409], f"replay: the app answered {deliveries(site)}"
    return report


def revoke_once(site: Site, holder: Holder, founded: Founded, holding: Holding) -> SignedAct:
    """The one revoke: a lost prepare, its approval with the first answer of
    the app lost, and the exact replay; the app's own records show one
    effect. Returns the act."""
    operation = lost_prepare(site, holder, founded)
    nonce = site.signer_evidence(operation)["frozen_nonce"]
    signatures = site.signatures()
    baseline = receiver_snapshot(site.secrets_query, holding, nonce, schema=site.secrets_schema)
    first_delivery = deliver_once_lost(site, holder, operation)
    act = first_delivery["act"]
    assert act.nonce == nonce, f"approval: the signed act's nonce {act.nonce} is not the frozen {nonce}"
    assert site.signatures() == signatures + 1, "approval: not exactly one new signature"
    subject = baseline["holding"]["subject"]
    first = receiver_snapshot(site.secrets_query, holding, nonce, subject, act.sha256,
                               schema=site.secrets_schema)
    replay_delivery(site, holder, operation, act)
    assert site.signatures() == signatures + 1, "replay: a new signature"
    replay = receiver_snapshot(site.secrets_query, holding, nonce, subject, act.sha256,
                               schema=site.secrets_schema)
    assert_one_effect(baseline, first, replay, act)
    return act

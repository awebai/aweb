"""Pure codecs and ancestry for docs/id-certificates.md; no authentication I/O.

A certificate signature alone establishes neither issuance authority nor current
validity. The chain verifier must check independently supplied authority/status.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from awid.did import did_from_public_key, public_key_from_did, validate_stable_id
from awid.utc_timestamps import parse_utc_seconds
from awid.identity_log_verify import verify_identity_log
from awid.federation_errors import FederationAuthorityError

ID_CERTIFICATE_PREFIX = b"aweb.id-certificate/1\n"
ID_CHAIN_MAX_DEPTH = 8
ID_CHAIN_MAX_BYTES = 6144
ID_CHAIN_HEADER_MAX_BYTES = 8192
_FIELDS = frozenset({"v", "type", "id", "domain", "parent", "kind", "issuer_key", "issued_at"})
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_BASE58 = re.compile(r"[1-9A-HJ-NP-Za-km-z]+")
_ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493


class IDCertificateError(ValueError):
    """A contract refusal; ``code`` is stable, prose is diagnostic only."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _canonical(value: Any) -> bytes:
    def check(node: Any) -> None:
        if node is None or type(node) in (bool, int):
            return
        if type(node) is str:
            node.encode("utf-8", errors="strict")
        elif type(node) is list:
            for item in node:
                check(item)
        elif type(node) is dict and all(type(key) is str for key in node):
            for key, item in node.items():
                key.encode("utf-8", errors="strict")
                check(item)
        else:
            raise IDCertificateError("invalid_shape")
    try:
        check(value)
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (UnicodeError, RecursionError) as exc:
        raise IDCertificateError("invalid_json") from exc
    except ValueError as exc:
        raise IDCertificateError("invalid_shape") from exc


def id_certificate_signing_bytes(certificate: dict[str, Any]) -> bytes:
    """Compute canonical bytes, including for negative shape-test fixtures.

    This low-level operation does not validate or confer certificate authority.
    """
    return ID_CERTIFICATE_PREFIX + _canonical(certificate)


def id_certificate_id(certificate: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(id_certificate_signing_bytes(certificate)).hexdigest()


def _domain(value: Any) -> None:
    if not isinstance(value, str) or len(value) > 253 or not all(_LABEL.fullmatch(label) for label in value.split(".")):
        raise IDCertificateError("invalid_domain")


def _id(value: Any, *, key_only: bool = False) -> None:
    try:
        if not isinstance(value, str):
            raise ValueError("not text")
        if value.startswith("did:key:"):
            public = public_key_from_did(value)
            if did_from_public_key(public) != value or not crypto_core_ed25519_is_valid_point(public):
                raise ValueError("noncanonical or non-prime-subgroup key")
        elif not key_only and value.startswith("did:aw:"):
            if not _BASE58.fullmatch(value[7:]) or validate_stable_id(value) != value:
                raise ValueError("noncanonical stable id")
        else:
            raise ValueError("wrong ID kind")
    except (TypeError, ValueError) as exc:
        raise IDCertificateError("invalid_shape") from exc


def _shape(signed: Any) -> dict[str, Any]:
    if type(signed) is not dict or set(signed) != {"certificate", "signature"}:
        raise IDCertificateError("invalid_shape")
    c = signed["certificate"]
    if type(c) is not dict or set(c) != _FIELDS:
        raise IDCertificateError("invalid_shape")
    if type(c["v"]) is not int or c["v"] != 1 or c["type"] != "aweb.id-certificate":
        raise IDCertificateError("invalid_shape")
    if c["kind"] not in ("human", "agent"):
        raise IDCertificateError("invalid_kind")
    _id(c["id"])
    if c["kind"] == "human" and not c["id"].startswith("did:aw:"):
        raise IDCertificateError("invalid_shape")
    _domain(c["domain"])
    parent = c["parent"]
    if type(parent) is not dict or set(parent) != {"kind", "id"}:
        raise IDCertificateError("invalid_shape")
    if parent["kind"] == "identity":
        _id(parent["id"])
    elif parent["kind"] == "namespace":
        _domain(parent["id"])
        if parent["id"] != c["domain"]:
            raise IDCertificateError("domain_mismatch")
    else:
        raise IDCertificateError("invalid_shape")
    _id(c["issuer_key"], key_only=True)
    try:
        parse_utc_seconds(c["issued_at"])
    except ValueError as exc:
        raise IDCertificateError("invalid_shape") from exc
    return c


def _decode_b64(value: Any) -> bytes:
    if not isinstance(value, str) or not _B64URL.fullmatch(value):
        raise IDCertificateError("invalid_encoding")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise IDCertificateError("invalid_encoding") from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise IDCertificateError("invalid_encoding")
    return decoded


def verify_id_certificate(signed: dict[str, Any], *, issuer_key: str) -> None:
    """Check shape and signature with an independently selected issuer key."""
    c = _shape(signed)
    signature = _decode_b64(signed["signature"])
    if len(signature) != 64:
        raise IDCertificateError("invalid_encoding")
    if c["issuer_key"] != issuer_key:
        raise IDCertificateError("invalid_signature")
    # This profile requires canonical, nonidentity prime-subgroup R and S<L.
    # Library verification alone can accept a mixed-order A for some messages.
    # Redundant with tested PyNaCl/libsodium; kept to pin the profile.
    if (
        not crypto_core_ed25519_is_valid_point(signature[:32])
        or int.from_bytes(signature[32:], "little") >= _ED25519_ORDER
    ):
        raise IDCertificateError("invalid_signature")
    try:
        VerifyKey(public_key_from_did(issuer_key)).verify(id_certificate_signing_bytes(c), signature)
    except (BadSignatureError, ValueError, TypeError) as exc:
        raise IDCertificateError("invalid_signature") from exc


def _bundle_shape(bundle: Any) -> None:
    if type(bundle) is not dict or set(bundle) != {"v", "type", "certificates"}:
        raise IDCertificateError("invalid_shape")
    if type(bundle["v"]) is not int or bundle["v"] != 1 or bundle["type"] != "aweb.id-chain":
        raise IDCertificateError("invalid_shape")
    certs = bundle["certificates"]
    if type(certs) is not list or not certs:
        raise IDCertificateError("invalid_shape")
    if len(certs) > ID_CHAIN_MAX_DEPTH:
        raise IDCertificateError("depth_exceeded")
    for signed in certs:
        c = _shape(signed)
        verify_id_certificate(signed, issuer_key=c["issuer_key"])


def encode_id_chain_header(bundle: dict[str, Any]) -> str:
    raw = _canonical(bundle)
    if len(raw) > ID_CHAIN_MAX_BYTES:
        raise IDCertificateError("bundle_too_large")
    _bundle_shape(bundle)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_id_chain_header(value: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise IDCertificateError("invalid_encoding")
    if len(value) > ID_CHAIN_HEADER_MAX_BYTES:
        raise IDCertificateError("bundle_too_large")
    raw = _decode_b64(value)
    if len(raw) > ID_CHAIN_MAX_BYTES:
        raise IDCertificateError("bundle_too_large")
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise IDCertificateError("invalid_json")
            result[key] = item
        return result
    def reject_number(_: str) -> Any:
        raise IDCertificateError("invalid_shape")
    try:
        bundle = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=reject_number, parse_constant=reject_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise IDCertificateError("invalid_json") from exc
    except IDCertificateError:
        raise
    except ValueError as exc:
        # json's integer digit limit is a shape refusal, not an uncoded error.
        raise IDCertificateError("invalid_shape") from exc
    if _canonical(bundle) != raw:
        raise IDCertificateError("noncanonical_json")
    _bundle_shape(bundle)
    return bundle

# Evidence is trusted host input, never an agent's request body.


@dataclass(frozen=True)
class IDChainEvidence:
    status: dict[str, Any]
    namespace_authority: dict[str, Any]
    age_seconds: float | None
    refresh_failed: bool = False


def status_cache_mode(age_seconds: float | None, refresh_failed: bool) -> str:
    if type(age_seconds) not in (int, float) or not math.isfinite(age_seconds) or age_seconds < 0:
        return 'unavailable'
    if age_seconds <= 60:
        return 'fresh'
    return 'outage_grace' if refresh_failed and age_seconds <= 900 else 'unavailable'


def status_request(bundle: dict[str, Any] | None, subject: dict[str, Any], *, domain: str | None = None) -> dict[str, Any] | None:
    """Omitted local proof creates no registry dependency; domain is private."""
    if bundle is None:
        if subject['id'].startswith('did:key:'):
            return None
        if domain is None:
            raise IDCertificateError('evidence_unavailable')
        _domain(domain)
        return {'v': 1, 'domain': domain, 'ids': [subject['id']]}
    if len(_canonical(bundle)) > ID_CHAIN_MAX_BYTES:
        raise IDCertificateError('bundle_too_large')
    _bundle_shape(bundle)
    selected = bundle['certificates'][0]['certificate']['domain']
    if domain is not None and selected != domain:
        raise IDCertificateError('domain_mismatch')
    return {'v': 1, 'domain': selected, 'ids': list(dict.fromkeys(s['certificate']['id'] for s in bundle['certificates'] if s['certificate']['id'].startswith('did:aw:')))}


def request_disposition(result: dict[str, Any], *, subject: dict[str, Any], original_auth_passed: bool, human_required: bool = False) -> str:
    if not original_auth_passed:
        return 'refuse'
    if human_required:
        return 'continue' if result['outcome'] == 'nearest_human' and result['identity_valid'] is True else 'refuse'
    if result['identity_valid'] is True or result['reason'] in ('legacy_no_chain', 'unregistered_identity'):
        return 'continue'
    if subject['id'].startswith('did:key:') and result['reason'] in ('stale_issuer_key', 'status_expired', 'evidence_unavailable'):
        return 'continue'
    return 'refuse'


def _fields(value: Any, fields: str) -> None:
    if type(value) is not dict or set(value) != set(fields.split()):
        raise IDCertificateError('evidence_unavailable')


def _sequence(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 2**53 - 1:
        raise IDCertificateError('evidence_unavailable')
    return value


def _witness(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z', value):
        raise IDCertificateError('evidence_unavailable')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise IDCertificateError('evidence_unavailable') from exc


class _IDStatus:
    def __init__(self, evidence: IDChainEvidence, domain: str):
        s, authority = evidence.status, evidence.namespace_authority
        try:
            if len(_canonical(s)) > 131072:
                raise IDCertificateError('evidence_unavailable')
            _fields(s, 'v domain observed_at namespace identities missing')
            if type(s['v']) is not int or s['v'] != 1 or s['domain'] != domain:
                raise IDCertificateError('evidence_unavailable')
            self.now = _witness(s['observed_at'])
            _fields(s['namespace'], 'epochs')
            self.epochs = s['namespace']['epochs']
            if type(self.epochs) is not list or not self.epochs:
                raise IDCertificateError('evidence_unavailable')
            for n, e in enumerate(self.epochs):
                _fields(e, 'seq did_key registered_at retired_at continuity')
                if _sequence(e['seq']) != n + 1 or e['continuity'] not in ('rotated', 'replaced'):
                    raise IDCertificateError('evidence_unavailable')
                _id(e['did_key'], key_only=True)
                start = _witness(e['registered_at'])
                end = _witness(e['retired_at']) if e['retired_at'] is not None else None
                if start > self.now or (end is not None and (end < start or end > self.now)):
                    raise IDCertificateError('evidence_unavailable')
                if n == 0 and e['continuity'] != 'replaced':
                    raise IDCertificateError('evidence_unavailable')
                if n:
                    prev = self.epochs[n - 1]
                    if prev['retired_at'] is None or _witness(prev['retired_at']) > start:
                        raise IDCertificateError('evidence_unavailable')
                    if e['continuity'] == 'rotated' and prev['retired_at'] != e['registered_at']:
                        raise IDCertificateError('evidence_unavailable')
            if self.epochs[-1]['retired_at'] is not None:
                raise IDCertificateError('evidence_unavailable')
            _fields(authority, 'domain dns_name inherited controller_key')
            if (authority['domain'] != domain or authority['dns_name'] != '_awid.' + domain
                or authority['inherited'] is not False or authority['controller_key'] != self.epochs[-1]['did_key']):
                raise IDCertificateError('evidence_unavailable')
            self.cutoff = max(_witness(e['registered_at']) for e in self.epochs if e['continuity'] == 'replaced')
            self.identities: dict[str, dict[str, Any]] = {}
            if type(s['identities']) is not list or type(s['missing']) is not list:
                raise IDCertificateError('evidence_unavailable')
            for row in s['identities']:
                _fields(row, 'id current_certificate_id current_key_seq key_history certificates revocation')
                _id(row['id'])
                if not row['id'].startswith('did:aw:') or row['id'] in self.identities:
                    raise IDCertificateError('evidence_unavailable')
                if type(row['key_history']) is not list or not row['key_history']:
                    raise IDCertificateError('evidence_unavailable')
                entries = []
                for w in row['key_history']:
                    _fields(w, 'entry registered_at')
                    _witness(w['registered_at'])
                    _fields(w['entry'], 'seq operation previous_did_key new_did_key prev_entry_hash entry_hash state_hash authorized_by signature timestamp')
                    _id(w['entry']['new_did_key'], key_only=True)
                    _id(w['entry']['authorized_by'], key_only=True)
                    entries.append(w['entry'])
                if _sequence(row['current_key_seq']) != len(entries):
                    raise IDCertificateError('evidence_unavailable')
                # Released DID-log verification: timestamps prove continuity,
                # never admission or an issuer key-version time window.
                verify_identity_log(did_aw=row['id'], entries=entries, expected_current_did_key=entries[-1]['new_did_key'])
                if type(row['certificates']) is not list or not row['certificates']:
                    raise IDCertificateError('evidence_unavailable')
                digests = set()
                for n, rev in enumerate(row['certificates']):
                    _fields(rev, 'signed registered_at superseded_at issuer_key_seq')
                    c = _shape(rev['signed'])
                    verify_id_certificate(rev['signed'], issuer_key=c['issuer_key'])
                    if c['id'] != row['id'] or c['domain'] != domain:
                        raise IDCertificateError('evidence_unavailable')
                    digest = id_certificate_id(c)
                    if digest in digests:
                        raise IDCertificateError('evidence_unavailable')
                    digests.add(digest)
                    start = _witness(rev['registered_at'])
                    end = _witness(rev['superseded_at']) if rev['superseded_at'] is not None else None
                    if start > self.now or (end is not None and (end <= start or end > self.now)):
                        raise IDCertificateError('evidence_unavailable')
                    if n and row['certificates'][n - 1]['superseded_at'] != rev['registered_at']:
                        raise IDCertificateError('evidence_unavailable')
                    _sequence(rev['issuer_key_seq'])
                if row['certificates'][-1]['superseded_at'] is not None or row['current_certificate_id'] != id_certificate_id(row['certificates'][-1]['signed']['certificate']):
                    raise IDCertificateError('evidence_unavailable')
                if row['revocation'] is not None:
                    _fields(row['revocation'], 'revoked_at effective_from')
                    at, effective = _witness(row['revocation']['revoked_at']), _witness(row['revocation']['effective_from'])
                    if at > self.now or effective > at:
                        raise IDCertificateError('evidence_unavailable')
                self.identities[row['id']] = row
            self.missing = set()
            for missing in s['missing']:
                _id(missing)
                if not missing.startswith('did:aw:') or missing in self.identities or missing in self.missing:
                    raise IDCertificateError('evidence_unavailable')
                self.missing.add(missing)
            for row in self.identities.values():
                for revision in row['certificates']:
                    c = revision['signed']['certificate']
                    if c['parent']['kind'] == 'namespace':
                        epoch = self.epoch(revision['issuer_key_seq'])
                        at = _witness(revision['registered_at'])
                        if at < _witness(epoch['registered_at']) or (epoch['retired_at'] is not None and at >= _witness(epoch['retired_at'])):
                            raise IDCertificateError('evidence_unavailable')
                        if c['issuer_key'] != epoch['did_key']:
                            raise IDCertificateError('evidence_unavailable')
                    elif c['parent']['id'] in self.identities:
                        parent_keys = self.identities[c['parent']['id']]['key_history']
                        seq = revision['issuer_key_seq']
                        if seq > len(parent_keys) or c['issuer_key'] != parent_keys[seq - 1]['entry']['new_did_key']:
                            raise IDCertificateError('evidence_unavailable')
        except (IDCertificateError, FederationAuthorityError, ValueError, TypeError, KeyError, RecursionError) as exc:
            raise IDCertificateError('evidence_unavailable') from exc

    def epoch(self, seq: int) -> dict[str, Any]:
        if not 1 <= seq <= len(self.epochs):
            raise IDCertificateError('evidence_unavailable')
        return self.epochs[seq - 1]

    def row(self, identity: str) -> dict[str, Any]:
        if identity in self.missing:
            raise IDCertificateError('unregistered_identity')
        if identity not in self.identities:
            raise IDCertificateError('evidence_unavailable')
        return self.identities[identity]

    def revision(self, identity: str, at: datetime) -> dict[str, Any]:
        found = [r for r in self.row(identity)['certificates'] if _witness(r['registered_at']) <= at and (r['superseded_at'] is None or at < _witness(r['superseded_at']))]
        if len(found) != 1:
            raise IDCertificateError('evidence_unavailable')
        return found[0]

    def current_key(self, identity: str) -> str:
        return identity if identity.startswith('did:key:') else self.row(identity)['key_history'][-1]['entry']['new_did_key']

    def issuer(self, c: dict[str, Any], revision: dict[str, Any] | None) -> str:
        parent = c['parent']
        if parent['kind'] == 'namespace':
            return self.epoch(revision['issuer_key_seq'])['did_key'] if revision else self.epochs[-1]['did_key']
        if revision:
            if parent['id'].startswith('did:key:'):
                raise IDCertificateError('unregistered_parent')
            keys = self.row(parent['id'])['key_history']
            seq = revision['issuer_key_seq']
            if not 1 <= seq <= len(keys):
                raise IDCertificateError('evidence_unavailable')
            return keys[seq - 1]['entry']['new_did_key']
        return self.current_key(parent['id'])


def _chain_structure(certs: list[dict[str, Any]]) -> None:
    ids = [s['certificate']['id'] for s in certs]
    if len(ids) != len(set(ids)):
        raise IDCertificateError('duplicate_id')
    by = {s['certificate']['id']: s['certificate'] for s in certs}
    for identity in by:
        seen = set()
        while identity in by:
            if identity in seen:
                raise IDCertificateError('cycle')
            seen.add(identity)
            parent = by[identity]['parent']
            identity = parent['id'] if parent['kind'] == 'identity' else None
    domain = certs[0]['certificate']['domain']
    for n, signed in enumerate(certs):
        c = signed['certificate']
        if c['domain'] != domain:
            raise IDCertificateError('domain_mismatch')
        if n == 0:
            if c['parent'] != {'kind': 'namespace', 'id': domain}:
                raise IDCertificateError('missing_parent')
        else:
            p = certs[n - 1]['certificate']
            if c['parent'] != {'kind': 'identity', 'id': p['id']}:
                raise IDCertificateError('missing_parent')
            if c['kind'] == 'human' and p['kind'] != 'human':
                raise IDCertificateError('human_issuer_is_agent')


def _id_chain(bundle: dict[str, Any] | None, subject: dict[str, Any], evidence: IDChainEvidence | None, domain: str | None) -> dict[str, Any]:
    plan = status_request(bundle, subject, domain=domain)
    if plan is None:
        raise IDCertificateError('legacy_no_chain')
    domain = plan['domain']
    certs = bundle['certificates'] if bundle is not None else None
    if certs is not None:
        if len(_canonical(bundle)) > ID_CHAIN_MAX_BYTES:
            raise IDCertificateError('bundle_too_large')
        _chain_structure(certs)
        if certs[-1]['certificate']['id'] != subject['id']:
            raise IDCertificateError('subject_mismatch')
    if subject.get('team_member_did_key') not in (None, '') and subject['team_member_did_key'] != subject['did_key']:
        raise IDCertificateError('subject_mismatch')
    if subject.get('team_member_did_aw') not in (None, '') and subject['team_member_did_aw'] != subject['id']:
        raise IDCertificateError('subject_mismatch')
    if subject['id'].startswith('did:key:') and subject['id'] != subject['did_key']:
        raise IDCertificateError('subject_mismatch')
    if evidence is None:
        raise IDCertificateError('evidence_unavailable')
    if status_cache_mode(evidence.age_seconds, evidence.refresh_failed) == 'unavailable':
        raise IDCertificateError('status_expired' if evidence.age_seconds is not None and evidence.age_seconds > 900 else 'evidence_unavailable')
    status = _IDStatus(evidence, domain)
    if subject['id'].startswith('did:aw:') and status.current_key(subject['id']) != subject['did_key']:
        raise IDCertificateError('subject_mismatch')
    if certs is None:
        certs = []
        identity = subject['id']
        seen = set()
        while True:
            if identity in seen:
                raise IDCertificateError('cycle')
            if len(certs) >= ID_CHAIN_MAX_DEPTH:
                raise IDCertificateError('depth_exceeded')
            seen.add(identity)
            signed = status.revision(identity, status.now)['signed']
            certs.insert(0, signed)
            if signed['certificate']['parent']['kind'] == 'namespace':
                break
            identity = signed['certificate']['parent']['id']
        _chain_structure(certs)
    by = {s['certificate']['id']: s for s in certs}
    for signed in certs:
        c = signed['certificate']
        if c['id'].startswith('did:aw:') and status.row(c['id'])['current_certificate_id'] != id_certificate_id(c):
            raise IDCertificateError('superseded_certificate')
    for signed in certs:
        c = signed['certificate']
        revision = status.revision(c['id'], status.now) if c['id'].startswith('did:aw:') else None
        issuer = status.issuer(c, revision)
        if c['issuer_key'] != issuer:
            raise IDCertificateError('stale_issuer_key')
        verify_id_certificate(signed, issuer_key=issuer)

    def evaluate(identity: str, at: datetime, path: frozenset[str]) -> str | None:
        if identity in path:
            raise IDCertificateError('cycle')
        if len(path) >= ID_CHAIN_MAX_DEPTH:
            raise IDCertificateError('depth_exceeded')
        revision = status.revision(identity, at) if identity.startswith('did:aw:') else None
        signed = revision['signed'] if revision else by.get(identity)
        if signed is None:
            raise IDCertificateError('evidence_unavailable')
        c = signed['certificate']
        if c['domain'] != domain:
            raise IDCertificateError('domain_mismatch')
        if revision:
            if _witness(revision['registered_at']) < status.cutoff:
                raise IDCertificateError('root_replaced')
            revocation = status.row(identity)['revocation']
            if revocation and _witness(revocation['effective_from']) <= at:
                raise IDCertificateError('revoked')
        issuer = status.issuer(c, revision)
        if issuer != c['issuer_key']:
            raise IDCertificateError('stale_issuer_key')
        verify_id_certificate(signed, issuer_key=issuer)
        parent = c['parent']
        human = None
        if parent['kind'] == 'identity':
            parent_at = _witness(revision['registered_at']) if c['kind'] == 'human' and revision else at
            p = status.revision(parent['id'], parent_at)['signed'] if parent['id'].startswith('did:aw:') else by.get(parent['id'])
            if p is None:
                raise IDCertificateError('evidence_unavailable')
            if c['kind'] == 'human' and p['certificate']['kind'] != 'human':
                raise IDCertificateError('human_issuer_is_agent')
            human = evaluate(parent['id'], parent_at, path | {identity})
        return identity if c['kind'] == 'human' else human

    human = evaluate(subject['id'], status.now, frozenset())
    return {'outcome': 'nearest_human' if human else 'no_human', 'human_id': human, 'identity_valid': True, 'kind': certs[-1]['certificate']['kind'], 'reason': 'verified'}


def verify_id_chain(bundle: dict[str, Any] | None, *, subject: dict[str, Any], evidence: IDChainEvidence | None, domain: str | None = None) -> dict[str, Any]:
    """Pure authority verification. Original auth and current roles stay separate."""
    try:
        return _id_chain(bundle, subject, evidence, domain)
    except IDCertificateError as exc:
        reason = exc.code
        unavailable = reason in ('status_expired', 'evidence_unavailable')
        return {'outcome': 'unavailable' if unavailable else 'unknown', 'human_id': None,
                'identity_valid': None if unavailable or reason in ('legacy_no_chain', 'unregistered_identity') else False,
                'kind': None, 'reason': reason}

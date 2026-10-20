"""Member-signed HTTP with one verified certificate-replacement recovery.

The caller supplies its own member key and trusted registry client. A naapp
verifier never receives a member's private key and never performs this recovery
on behalf of an incoming request.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

import httpx
from awid.contract import normalize_identity_scope
from awid.certificates import certificate_timestamp
from awid.did import did_from_public_key
from awid.log import canonical_server_origin
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from awid.team_ids import parse_team_id
from nacl.signing import SigningKey


class TeamCertificateHTTPClient:
    def __init__(self, http: httpx.AsyncClient, *, origin: str, certificate: dict,
                 member_signing_key: bytes, registry: RegistryClient,
                 install: Callable[[dict], Awaitable[None]]):
        self.http, self.origin = http, canonical_server_origin(origin)
        self.certificate, self.key, self.registry, self.install = certificate, member_signing_key, registry, install
        self._proactive_checked_at = float('-inf')
        if certificate.get('member_did_key') != did_from_public_key(bytes(SigningKey(member_signing_key).verify_key)):
            raise ValueError('Member key does not match certificate')

    async def request(self, method: str, path: str, *, content: bytes = b'') -> httpx.Response:
        if not path.startswith('/') or '#' in path:
            raise ValueError('An exact request path is required')
        await self.refresh_if_due()
        for attempt in range(2):
            request = self.http.build_request(method, self.origin + path, content=content)
            timestamp = datetime.now(timezone.utc).isoformat()
            payload = canonical_json_bytes(dict(v=2, aud=self.origin, method=method.upper(),
                path=request.url.raw_path.decode('ascii'), team_id=self.certificate['team_id'],
                timestamp=timestamp, body_sha256=hashlib.sha256(content).hexdigest()))
            request.headers.update({
                'Authorization': f"DIDKey {self.certificate['member_did_key']} {sign_message(self.key, payload)}",
                'X-AWEB-Timestamp': timestamp,
                'X-AWEB-Signed-Payload': base64.urlsafe_b64encode(payload).rstrip(b'=').decode(),
                'X-AWID-Team-Certificate': base64.b64encode(json.dumps(self.certificate).encode()).decode(),
                'X-AWEB-Certificate-Versions': '1,2',
            })
            response = await self.http.send(request, follow_redirects=False)
            if attempt or response.status_code != 401:
                return response
            try:
                detail = response.json().get('detail')
            except (ValueError, AttributeError):
                return response
            if not isinstance(detail, dict) or detail.get('code') != 'certificate_replaced' or not isinstance(detail.get('replacement_certificate_id'), str):
                return response
            domain, name = parse_team_id(self.certificate['team_id'])
            fresh = await self.registry.fetch_team_certificate(domain, name, detail['replacement_certificate_id'], self.key)
            if fresh['certificate_id'] == self.certificate['certificate_id']:
                raise ValueError('Replacement certificate changes membership')
            await response.aclose()
            await self._install_verified_membership(fresh)
        raise AssertionError('Unreachable certificate retry state')

    async def refresh_if_due(self) -> None:
        """Pick up a controller-issued replacement in the final third, if finite."""
        if 'expires_at' not in self.certificate:
            return
        issued = certificate_timestamp(self.certificate.get('issued_at'), 'issued_at')
        expires = certificate_timestamp(self.certificate['expires_at'], 'expires_at')
        if datetime.now(timezone.utc) < expires - (expires - issued) / 3:
            return
        if time.monotonic() - self._proactive_checked_at < 30:
            return
        domain, name = parse_team_id(self.certificate['team_id'])
        fresh = await self.registry.fetch_current_member_certificate(domain, name, self.certificate['alias'], self.key)
        await self._install_verified_membership(fresh)
        self._proactive_checked_at = time.monotonic()

    async def _install_verified_membership(self, fresh: dict) -> None:
        for field in ('member_did_key', 'team_id', 'alias', 'member_did_aw', 'member_address'):
            if (fresh.get(field) or '') != (self.certificate.get(field) or ''):
                raise ValueError('Replacement certificate changes membership')
        scope = lambda cert: normalize_identity_scope(cert.get('identity_scope') or cert.get('lifetime'))
        if scope(fresh) != scope(self.certificate):
            raise ValueError('Replacement certificate changes membership')
        await self.install(fresh)
        self.certificate = fresh

"""Pinned-IP HTTP/1.1 transport for strict external registry evidence."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlsplit

import httpcore

from awid.federation_errors import FederationAuthorityError


@dataclass
class PinnedRegistryHTTP:
    """A transport generation that cannot resolve or redirect after validation."""

    origin: str
    approved_ips: tuple[str, ...]
    authority_generation: int
    timeout_seconds: float = 5.0
    max_response_bytes: int = 10 * 1024 * 1024
    max_error_bytes: int = 64 * 1024
    ssl_context: ssl.SSLContext | None = None
    selected_ip: str | None = None
    _pool: httpcore.AsyncConnectionPool = field(init=False, repr=False)
    _scheme: str = field(init=False, repr=False)
    _hostname: str = field(init=False, repr=False)
    _port: int = field(init=False, repr=False)
    _host_header: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        parsed = urlsplit(self.origin)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise FederationAuthorityError("sender_registry_origin_forbidden")
        if not self.approved_ips or self.authority_generation < 1:
            raise FederationAuthorityError("sender_registry_origin_forbidden")
        canonical_ips: list[str] = []
        for value in self.approved_ips:
            try:
                canonical = str(ipaddress.ip_address(value))
            except ValueError as exc:
                raise FederationAuthorityError("sender_registry_origin_forbidden") from exc
            if canonical not in canonical_ips:
                canonical_ips.append(canonical)
        if self.selected_ip is None:
            self.selected_ip = canonical_ips[0]
        else:
            try:
                self.selected_ip = str(ipaddress.ip_address(self.selected_ip))
            except ValueError as exc:
                raise FederationAuthorityError("sender_registry_origin_forbidden") from exc
            if self.selected_ip not in canonical_ips:
                raise FederationAuthorityError("sender_registry_origin_forbidden")
        self.approved_ips = tuple(canonical_ips)
        self._scheme = parsed.scheme
        self._hostname = parsed.hostname.lower()
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        default_port = 443 if parsed.scheme == "https" else 80
        self._host_header = self._hostname
        if self._port != default_port:
            self._host_header = f"{self._host_header}:{self._port}"
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=self.ssl_context,
            proxy=None,
            max_connections=4,
            max_keepalive_connections=4,
            keepalive_expiry=min(self.timeout_seconds, 5.0),
            http1=True,
            http2=False,
            retries=0,
        )

    @property
    def pool_key(self) -> tuple[str, tuple[str, ...], int]:
        return (self.origin, self.approved_ips, self.authority_generation)

    def _url(self, path: str) -> str:
        if not path.startswith("/") or path.startswith("//"):
            raise FederationAuthorityError("sender_registry_protocol_invalid")
        assert self.selected_ip is not None
        host = f"[{self.selected_ip}]" if ":" in self.selected_ip else self.selected_ip
        default_port = 443 if self._scheme == "https" else 80
        authority = host if self._port == default_port else f"{host}:{self._port}"
        return f"{self._scheme}://{authority}{path}"

    async def get_json(self, path: str, *, bypass_cache: bool = False) -> Any:
        headers: list[tuple[bytes, bytes]] = [
            (b"Host", self._host_header.encode("ascii")),
            (b"Accept", b"application/json"),
            (b"Accept-Encoding", b"identity"),
            (b"User-Agent", b"aweb-federation-authority/1"),
            (b"Connection", b"keep-alive"),
        ]
        if bypass_cache:
            headers.append((b"Cache-Control", b"no-cache"))
        timeout = {
            "connect": self.timeout_seconds,
            "read": self.timeout_seconds,
            "write": self.timeout_seconds,
            "pool": self.timeout_seconds,
        }
        request = httpcore.Request(
            method=b"GET",
            url=self._url(path),
            headers=headers,
            extensions={
                "sni_hostname": self._hostname,
                "timeout": timeout,
            },
        )
        try:
            async with asyncio.timeout(self.timeout_seconds):
                response = await self._pool.handle_async_request(request)
                try:
                    response_headers = {
                        key.decode("ascii").lower(): value.decode("latin-1")
                        for key, value in response.headers
                    }
                    encoding = response_headers.get("content-encoding", "").strip().lower()
                    if encoding not in {"", "identity"}:
                        raise FederationAuthorityError("sender_registry_protocol_invalid")
                    limit = (
                        self.max_response_bytes
                        if 200 <= response.status < 300
                        else self.max_error_bytes
                    )
                    length = response_headers.get("content-length")
                    if length is not None:
                        try:
                            if int(length) > limit:
                                raise FederationAuthorityError("sender_identity_evidence_too_large")
                        except ValueError as exc:
                            raise FederationAuthorityError("sender_registry_protocol_invalid") from exc
                    body = bytearray()
                    async for chunk in response.aiter_stream():
                        if len(body) + len(chunk) > limit:
                            raise FederationAuthorityError("sender_identity_evidence_too_large")
                        body.extend(chunk)
                finally:
                    await response.aclose()
        except FederationAuthorityError:
            raise
        except (httpcore.ConnectTimeout, httpcore.ReadTimeout, httpcore.WriteTimeout, TimeoutError) as exc:
            raise FederationAuthorityError("sender_registry_unavailable") from exc
        except (httpcore.ConnectError, httpcore.NetworkError) as exc:
            if _contains_tls_error(exc):
                raise FederationAuthorityError("sender_registry_tls_invalid") from exc
            raise FederationAuthorityError("sender_registry_unavailable") from exc
        except Exception as exc:
            if _contains_tls_error(exc):
                raise FederationAuthorityError("sender_registry_tls_invalid") from exc
            raise FederationAuthorityError("sender_registry_protocol_invalid") from exc

        if 300 <= response.status < 400:
            raise FederationAuthorityError("sender_registry_protocol_invalid")
        if response.status == 404:
            raise FederationAuthorityError("sender_identity_not_found")
        if response.status == 429 or response.status >= 500:
            raise FederationAuthorityError("sender_registry_unavailable")
        if not 200 <= response.status < 300:
            raise FederationAuthorityError("sender_registry_protocol_invalid")
        if not body:
            return {}
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FederationAuthorityError("sender_registry_protocol_invalid") from exc

    async def aclose(self) -> None:
        await self._pool.aclose()


def escaped_path_component(value: str) -> str:
    return quote(value, safe="")


def _contains_tls_error(exc: BaseException) -> bool:
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, (ssl.SSLError, ssl.CertificateError)):
            return True
        current = current.__cause__ or current.__context__
    return "certificate" in str(exc).lower() or "tls" in str(exc).lower()

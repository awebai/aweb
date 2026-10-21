"""Origin-verified manifest discovery through the shared egress guard.

C3's synchronous selector owns catalog parsing, variant ordering and digest
checks. Its fetch callback bridges to async egress on the caller's event loop;
no network call, parser or URL/address policy is duplicated here.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from importlib.metadata import version
from urllib.parse import urlsplit

from aweb_naapp.egress import (
    AddressPolicy,
    Bounds,
    Destination,
    DnsResolver,
    Egress,
    HeaderRules,
    InternalDestinations,
    canonical_url,
    parse_destination,
)
from aweb_naapp.egress import EgressRefused
from aweb_naapp.manifest import (
    MAX_MANIFEST_BYTES,
    SUPPORTED_MANIFEST_VERSIONS,
    Manifest,
    ManifestError,
    load_manifest,
    select_variant,
)

from aweb.app_registry import normalize_digest, normalize_origin, reserved_app_ids
from aweb.service_errors import ServiceError


class ManifestFetchError(ServiceError):
    """An install refusal carrying the shared manifest code where available."""

    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class FetchedManifest:
    origin: str
    url: str
    digest: str
    data: bytes
    manifest: Manifest


class ManifestFetcher:
    def __init__(
        self,
        *,
        egress: Egress | None = None,
        destination: Destination | None = None,
        timeout: float = 30.0,
        max_bytes: int = MAX_MANIFEST_BYTES,
    ) -> None:
        if not 0 < max_bytes <= MAX_MANIFEST_BYTES:
            raise ValueError("manifest bound must be positive and at most 10 MiB")
        # Validate all bounds even if the supplied egress has its own defaults.
        Bounds(total_timeout=timeout, max_response_bytes=max_bytes)
        self.egress = egress or Egress(
            addresses=AddressPolicy(internal_destinations=InternalDestinations.DISABLED),
            resolver=DnsResolver(), user_agent=f"aweb-server/{version('aweb')}",
        )
        # Hosts may inject the real guard and an exact destination for a test
        # server. Neither is taken from an install request; production is public.
        self.destination = destination
        self.timeout = timeout
        self.max_bytes = max_bytes

    async def fetch(
        self, origin: str, *, expected_digest: str | None = None, manifest_version: int | None = None,
    ) -> FetchedManifest:
        try:
            origin = normalize_origin(origin)
            canonical = canonical_url(origin + "/")
            origin = "https://" + canonical.authority
        except (ServiceError, EgressRefused, ValueError) as exc:
            raise ManifestFetchError("origin_invalid", "A valid HTTPS app origin is required") from exc
        if manifest_version is not None and manifest_version not in SUPPORTED_MANIFEST_VERSIONS:
            raise ManifestFetchError("manifest_version_unsupported", "Pinned manifest version is not supported")
        supported = SUPPORTED_MANIFEST_VERSIONS if manifest_version is None else (manifest_version,)
        expected = normalize_digest(expected_digest) if expected_digest is not None else None
        parsed = urlsplit(origin)
        loop = asyncio.get_running_loop()
        rules = HeaderRules(injected=[], amz_allowed=[], is_credential=lambda _value: False)

        async def send(path: str, limit: int) -> tuple[int, bytes]:
            destination = self.destination or parse_destination({
                "host": parsed.hostname, "port": parsed.port or 443,
                "path": path, "methods": ["GET"],
            }, internal_destinations=InternalDestinations.DISABLED)
            response = await self.egress.send(
                "GET", origin + path, destination, header_rules=rules,
                bounds=Bounds(
                    total_timeout=self.timeout,
                    max_response_bytes=min(limit, self.max_bytes),
                ),
            )
            if response.truncated:
                raise ValueError("manifest response exceeds its byte bound")
            return response.status, response.body

        def fetch(path: str, limit: int) -> tuple[int, bytes]:
            # C3 calls this only from the selector thread. Egress, DNS and TLS
            # remain on the active async loop, including in the real TLS tests.
            return asyncio.run_coroutine_threadsafe(send(path, limit), loop).result(self.timeout + 1)

        try:
            selected = await asyncio.to_thread(select_variant, origin, supported, fetch)
            manifest = load_manifest(selected.data, reserved_names=reserved_app_ids())
        except ManifestError as exc:
            status = 502 if exc.code.endswith("_unavailable") else 422
            raise ManifestFetchError(exc.code, "The app manifest could not be fetched or validated", status) from exc
        if normalize_origin(manifest.document["app"]["origin"]) != origin:
            raise ManifestFetchError("manifest_origin_mismatch", "Manifest origin differs from the fetched origin")
        if expected is not None and selected.digest != expected:
            raise ManifestFetchError("manifest_changed", "Manifest bytes changed; preview them again", 409)
        return FetchedManifest(origin, selected.url, selected.digest, selected.data, manifest)


def fetch_app_manifest(origin: str, *, timeout: float = 30.0, max_bytes: int = MAX_MANIFEST_BYTES) -> bytes:
    """Synchronous operator-command adapter to the same verified discovery."""
    return asyncio.run(ManifestFetcher(timeout=timeout, max_bytes=max_bytes).fetch(origin)).data

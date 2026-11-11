"""One public exact-subject binding and registered-kind observation path.

Observations use the public registry and certificate verifier. They establish
identity facts, never role, installation or resource authority. Resolve remote
facts before an effect transaction; consumers retain their own authority fence.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from awid.did import stable_id_from_did_key
from awid.id_certificates import IDCertificateError, status_request, verify_id_chain
from awid.registry_types import DIDKeyNotFoundError, IDTreeEnrollment, RegistryError

logger = logging.getLogger(__name__)


class IdentityObservationRefused(ValueError):
    """A binding mismatch or unavailable evidence; no web-framework dependency."""

    def __init__(
        self, code: Literal["identity_binding_mismatch", "identity_binding_unavailable"]
    ) -> None:
        if code not in ("identity_binding_mismatch", "identity_binding_unavailable"):
            raise ValueError("unknown identity observation refusal")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class IdentityBinding:
    did_aw: str = ""
    address: str = ""
    fresh_observation: bool = False
    self_derived: bool = False
    did_key: str = ""
    id_tree: IDTreeEnrollment | None = None


async def observe_identity_binding(
    client, *, did_key: str, did_aw: str, address: str = ""
) -> IdentityBinding:
    """Return a fresh key-bound observation for trusted in-process provisioning.

    Call before opening a provisioning transaction. This is the authoritative
    producer of IdentityBinding: it reads AWID fresh and applies the same
    identity/address rules as request authentication. A mismatch or unavailable
    evidence raises IdentityObservationRefused with its fixed classification;
    never construct a fresh observation from a certificate or transport input.
    """
    if not did_aw or not did_aw.startswith("did:aw:"):
        raise IdentityObservationRefused("identity_binding_mismatch")
    self_derived = False
    enrollment = None
    try:
        try:
            # The SDK's ordinary key/address caches have a longer lifetime
            # and can serve stale values. They cannot establish this binding.
            resolution = await client.resolve_key_fresh(did_aw)
        except RegistryError as exc:
            if exc.status_code != 404:
                raise
            if did_aw != stable_id_from_did_key(did_key):
                raise IdentityObservationRefused("identity_binding_mismatch") from exc
            self_derived = True
            # Key absence proves no enrollment only when AWID states it.
            enrollment = exc.id_tree if isinstance(exc, DIDKeyNotFoundError) else None
        else:
            if resolution.did_aw != did_aw or resolution.current_did_key != did_key:
                raise IdentityObservationRefused("identity_binding_mismatch")
            enrollment = resolution.id_tree
        if address:
            domain, separator, name = address.partition("/")
            if not separator or not domain or not name or "/" in name:
                raise IdentityObservationRefused("identity_binding_mismatch")
            resolved_address = await client.resolve_address_fresh(domain, name)
            if (
                resolved_address is None
                or resolved_address.did_aw != did_aw
                or resolved_address.current_did_key != did_key
                or f"{resolved_address.domain}/{resolved_address.name}" != address
            ):
                raise IdentityObservationRefused("identity_binding_mismatch")
    except IdentityObservationRefused:
        raise
    except RegistryError as exc:
        if exc.status_code == 404:
            raise IdentityObservationRefused("identity_binding_mismatch") from exc
        logger.warning("Identity binding registry dependency failed", exc_info=True)
        raise IdentityObservationRefused("identity_binding_unavailable") from exc
    except Exception as exc:
        logger.warning("Identity binding registry dependency failed", exc_info=True)
        raise IdentityObservationRefused("identity_binding_unavailable") from exc
    return IdentityBinding(
        did_aw,
        address,
        fresh_observation=True,
        self_derived=self_derived,
        did_key=did_key,
        id_tree=enrollment,
    )


@dataclass(frozen=True)
class IdentityKindObservation:
    """Trusted in-process verifier output, not a request DTO or credential."""

    did_key: str
    did_aw: str
    result: Mapping[str, Any]
    # Original producer age, for consumers carrying evidence across authority
    # waits. This in-process metadata changes neither classification nor equality.
    evidence_age_seconds: float | None = field(default=None, compare=False)

    @property
    def is_human(self) -> bool:
        return self.result["identity_valid"] is True and self.result["kind"] == "human"


def unverified_kind(reason: str) -> dict[str, Any]:
    unavailable = reason in ("evidence_unavailable", "status_expired")
    return {
        "outcome": "unavailable" if unavailable else "unknown",
        "human_id": None,
        "identity_valid": None
        if unavailable or reason == "unregistered_identity"
        else False,
        "kind": None,
        "reason": reason,
    }


async def observe_identity_kind(
    registry_client, binding: IdentityBinding, bundle=None
) -> IdentityKindObservation:
    """Verify the exact bound subject using the public verifier and cached evidence.

    Original authentication and fresh global identity binding belong to the
    caller. Unknown/unavailable/invalid results are returned for its existing
    disposition policy; none can establish human kind. No registry fallback or
    team/address inference is performed here.
    """
    subject = {"id": binding.did_aw or binding.did_key, "did_key": binding.did_key}
    evidence_age_seconds = None
    try:
        enrollment = binding.id_tree
        if binding.did_aw and enrollment is None:
            result = unverified_kind("evidence_unavailable")
        elif (
            binding.did_aw
            and enrollment is not None
            and not enrollment.enrolled
            and bundle is None
        ):
            result = unverified_kind("unregistered_identity")
        else:
            domain = (
                enrollment.domain
                if binding.did_aw and enrollment is not None and enrollment.enrolled
                else None
            )
            plan = status_request(bundle, subject, domain=domain)
            evidence = None
            if plan is not None:
                cached_evidence = getattr(registry_client, "id_chain_evidence", None)
                if callable(cached_evidence):
                    try:
                        evidence = await cached_evidence(
                            bundle, subject, domain=plan["domain"]
                        )
                    except Exception:
                        logger.warning("ID-tree cached evidence failed", exc_info=True)
            if evidence is not None:
                evidence_age_seconds = evidence.age_seconds
            result = verify_id_chain(
                bundle, subject=subject, evidence=evidence, domain=domain
            )
    except IDCertificateError as exc:
        result = unverified_kind(exc.code)
    return IdentityKindObservation(
        binding.did_key, binding.did_aw, MappingProxyType(result), evidence_age_seconds
    )

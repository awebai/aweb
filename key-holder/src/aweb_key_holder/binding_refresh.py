"""Re-sign an existing enrollment under the holder's current public authority."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from approval_service.canonical import canonical
from approval_service.encoding import encode
from approval_service.verify import Trust
from approval_service.wire import domain, validate
from awid.controller_signing import ControllerDescriptor

from .auth import Caller
from .keys import HolderOperation
from .refusals import Refusal, Refused

if TYPE_CHECKING:
    from .enrollment import Holder, WireObject


def check_active_enrollment(
    row: Mapping[str, object], *, caller: Caller, trust: Trust
) -> None:
    """README.md: refresh preserves the enrolled person and identity key."""
    if caller.identity != trust.person or caller.key != trust.identity_key:
        raise Refused(Refusal.BINDING_REFRESH_PERSON_REQUIRED)
    if (
        row["person"] != trust.person
        or not row["active"]
        or row["retired_at"] is not None
    ):
        raise Refused(Refusal.BINDING_REFRESH_ENROLLMENT_CHANGED)
    if row["identity_key"] != trust.identity_key:
        raise Refused(Refusal.BINDING_REFRESH_IDENTITY_KEY_CHANGED)


@dataclass(frozen=True, kw_only=True)
class HolderBindingRefresher:
    holder: Holder

    async def packet(
        self, *, person: str, caller: Caller, body: WireObject, chain: list[WireObject]
    ) -> WireObject:
        """README.md:183-200: re-sign the same registered keys, never re-enrol.

        The service owns the active-binding compare-and-swap. The holder retains
        its original B and historical evidence and signs only that credential set.
        """
        holder = self.holder
        await holder.admit(caller, chain)
        holder.require_approval()
        if caller.identity != person:
            raise Refused(Refusal.BINDING_REFRESH_PERSON_REQUIRED)
        if (
            not isinstance(body, dict)
            or set(body) != {"previous_binding_commitment"}
            or not isinstance(body["previous_binding_commitment"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", body["previous_binding_commitment"])
            is None
        ):
            raise Refused(Refusal.BINDING_REFRESH_REQUEST_INVALID)
        root = holder.store.descriptor()
        trust = await holder.public.person(
            chain, person=person, identity_key=caller.key, organisation=root.domain
        )
        caller.check_time()
        with holder.store.connection() as database, database:
            database.execute("BEGIN IMMEDIATE")
            current = holder.store.descriptor_in_transaction(database)
            self._check_authority(caller=caller, trust=trust, root=current)
            row = database.execute(
                "SELECT * FROM enrollments WHERE person=?", (person,)
            ).fetchone()
            if row is None or not row["binding"]:
                raise Refused(Refusal.BINDING_REFRESH_ENROLLMENT_CHANGED)
            check_active_enrollment(dict(row), caller=caller, trust=trust)
            original = json.loads(row["binding"])
            validate("binding", original)
            binding_body = {
                **original["binding"],
                "issuer": current.did_key,
                "certificate": trust.certificate,
            }
            if (
                binding_body["origin"] != holder.approval_origin
                or binding_body["rp_id"] != holder.rp_id
            ):
                raise Refused(Refusal.BINDING_REFRESH_SITE_CHANGED)
            if (
                binding_body["person"] != person
                or binding_body["identity_key"] != caller.key
                or binding_body["organisation"] != current.domain
            ):
                raise Refused(Refusal.BINDING_REFRESH_ENROLLMENT_CHANGED)
            signed = {
                "binding": binding_body,
                "signature": encode(
                    holder.store.sign_authorized_payload(
                        database,
                        current,
                        domain("binding") + canonical(binding_body),
                        operation=HolderOperation.BINDING_REFRESH,
                        actor=caller.key,
                    )
                ),
            }
            self._check_authority(caller=caller, trust=trust, root=current)
            return {
                "version": 1,
                "requester": caller.descriptor,
                "previous_binding_commitment": body["previous_binding_commitment"],
                "binding": signed,
                "id_chain": chain,
            }

    @staticmethod
    def _check_authority(
        *, caller: Caller, trust: Trust, root: ControllerDescriptor
    ) -> None:
        caller.check_time()
        if (
            trust.namespace_issuer != root.did_key
            or not 0 <= int(time.time()) - trust.observed_at <= 60
        ):
            raise Refused(Refusal.IDENTITY_UNAVAILABLE)

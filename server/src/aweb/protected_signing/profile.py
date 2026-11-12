"""Public operator-provisioned service pins; configuration never grants authority."""

from __future__ import annotations

import json
import re
from typing import Annotated, Literal
from urllib.parse import urlsplit

from aweb_naapp.hooks.strictjson import MAX_SAFE_INTEGER, parse_strict
from awid.did import public_key_from_did, validate_stable_id
from awid.log import require_canonical_server_origin
from awid.team_ids import build_team_id, parse_team_id
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator


class ProfileRefused(ValueError):
    pass


def _text(value):
    if not value or value != value.strip():
        raise ValueError("nonempty exact text required")
    return value


def _domain(value):
    if len(value) > 253 or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*",
        value,
    ):
        raise ValueError("canonical namespace required")
    return value


def _key(value):
    public_key_from_did(value)
    return value


def _stable(value):
    if validate_stable_id(value) != value:
        raise ValueError("canonical stable ID required")
    return value


Text = Annotated[str, AfterValidator(_text)]
Domain = Annotated[str, AfterValidator(_domain)]
KeyDID = Annotated[str, AfterValidator(_key)]
StableDID = Annotated[str, AfterValidator(_stable)]
Origin = Annotated[str, AfterValidator(require_canonical_server_origin)]
Positive = Annotated[int, Field(strict=True, ge=1, le=MAX_SAFE_INTEGER)]
VersionOne = Annotated[int, Field(strict=True, ge=1, le=1)]


class _Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class NamespaceAuthority(_Closed):
    domain: Domain
    controller_did: KeyDID


class AuthorityReference(_Closed):
    kind: Literal["human_identity", "namespace_controller", "team_controller"]
    id: Text
    domain: Domain

    @model_validator(mode="after")
    def canonical_id(self):
        if self.kind == "human_identity":
            _stable(self.id)
        elif self.kind == "namespace_controller":
            if self.id != self.domain:
                raise ValueError("namespace authority mismatch")
        else:
            domain, name = parse_team_id(self.id)
            if domain != self.domain or build_team_id(domain, name) != self.id:
                raise ValueError("canonical team authority required")
        return self


class HumanReference(_Closed):
    id: StableDID
    domain: Domain


class ProfileScope(_Closed):
    v: VersionOne
    kind: Literal["protected_key"]
    service_id: Text
    authority: AuthorityReference
    human: HumanReference
    generation: Positive


class PolicyReference(_Closed):
    ref: Literal["aweb.human-assurance/1"]
    version: Positive


class ProfileBinding(_Closed):
    scope: ProfileScope
    authority_key_did: KeyDID
    policy: PolicyReference

    def context(self):
        from aweb_naapp.runtime.protected_signer import ProtectedKeyContext

        s = self.scope
        return ProtectedKeyContext(
            s.service_id,
            s.authority.kind,
            s.authority.id,
            s.authority.domain,
            s.human.id,
            s.human.domain,
            s.generation,
        )


class ProtectedServiceProfile(_Closed):
    v: VersionOne
    service_id: Text
    request_origin: Origin
    human_origin: Origin
    rp_id: Domain
    registry_origin: Origin
    namespace_authorities: Annotated[
        tuple[NamespaceAuthority, ...], Field(min_length=1)
    ]
    bindings: Annotated[tuple[ProfileBinding, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def references(self):
        human = urlsplit(self.human_origin)
        if human.scheme != "https" or human.hostname != self.rp_id:
            raise ValueError("human HTTPS origin/RP mismatch")
        namespaces = self.namespace_keys()
        if len(namespaces) != len(self.namespace_authorities):
            raise ValueError("duplicate namespace authority")
        seen, keys = set(), {}
        for binding in self.bindings:
            s, a, h = binding.scope, binding.scope.authority, binding.scope.human
            if (
                s.service_id != self.service_id
                or a.domain not in namespaces
                or h.domain not in namespaces
            ):
                raise ValueError("unconfigured service or namespace")
            authority = (a.kind, a.id, a.domain)
            stable = (*authority, h.id, h.domain)
            if stable in seen:
                raise ValueError("duplicate current binding")
            seen.add(stable)
            if authority in keys and keys[authority] != binding.authority_key_did:
                raise ValueError("conflicting authority key")
            keys[authority] = binding.authority_key_did
        return self

    @classmethod
    def from_json(cls, raw: bytes):
        try:
            if len(raw) > 65536:
                raise ValueError("profile too large")
            parse_strict(
                raw
            )  # Duplicate fields/numbers/depth follow the existing strict codec.
            return cls.model_validate_json(raw)
        except (ValueError, TypeError):
            # No rejected input, potential secret or private locator in errors.
            raise ProfileRefused("profile_invalid") from None

    def fields(self):
        return self.model_dump(mode="json")

    def namespace_keys(self):
        return {row.domain: row.controller_did for row in self.namespace_authorities}

    def binding_for(self, scope):
        for binding in self.bindings:
            if binding.scope.model_dump(mode="json") == scope:
                return binding
        raise ProfileRefused("profile_scope_refused")


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "profile", type=Path, help="operator-provisioned local JSON file"
    )
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                ProtectedServiceProfile.from_json(args.profile.read_bytes()).fields(),
                indent=2,
            )
        )
    except ProfileRefused as exc:
        parser.exit(2, str(exc) + "\n")

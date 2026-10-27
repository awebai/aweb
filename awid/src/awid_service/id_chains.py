"""Structural checks on a presented identity chain (docs/id-certificates.md §2, §5).

Pure checks that need no registry state: the bundle is ordered namespace child
first and leaf last, every link names the certificate before it as parent,
and R1/R3 hold on every link. Each certificate's shape and its signature under
its own issuer_key were already checked by awid.id_certificates when the
header was decoded; which issuer key carries authority is decided by the
registration gate under its locks.
"""

from __future__ import annotations

from awid_service.id_registration import RegistrationRefused


def check_chain_structure(chain: list[dict]) -> None:
    leaf = chain[-1]["certificate"]
    domain = leaf["domain"]
    seen: set[str] = set()
    previous = None
    for link in chain:
        cert = link["certificate"]
        parent = cert["parent"]
        if cert["domain"] != domain:
            raise RegistrationRefused("domain_mismatch")
        if cert["id"] in seen:
            raise RegistrationRefused("cycle" if cert["id"] == leaf["id"] else "duplicate_id")
        if previous is None:
            if parent["kind"] != "namespace":
                raise RegistrationRefused("missing_parent")
            if parent["id"] != domain:
                raise RegistrationRefused("domain_mismatch")
        else:
            if parent != {"kind": "identity", "id": previous["id"]}:
                raise RegistrationRefused("missing_parent")
            if cert["kind"] == "human" and previous["kind"] != "human":
                raise RegistrationRefused("human_issuer_is_agent")
        seen.add(cert["id"])
        previous = cert

"""Caller roles for the one strict authority-resolution workflow."""

from dataclasses import dataclass
from enum import Enum, StrEnum, auto

from awid.federation_errors import FederationErrorSpec, federation_error_spec

SENDER_IDENTITY_NOT_FOUND = federation_error_spec("sender_identity_not_found")
RECIPIENT_IDENTITY_NOT_FOUND = federation_error_spec("recipient_identity_not_found")
AUTHORITY_CAS_CONFLICT = federation_error_spec("federation_authority_cas_conflict")
RESOLVER_BUSY = federation_error_spec("federation_resolver_busy")


@dataclass(frozen=True)
class AuthorityLookupPolicy:
    missing_identity: FederationErrorSpec
    busy: FederationErrorSpec


SENDER_LOOKUP = AuthorityLookupPolicy(
    missing_identity=SENDER_IDENTITY_NOT_FOUND, busy=AUTHORITY_CAS_CONFLICT
)
CONTACT_LOOKUP = AuthorityLookupPolicy(
    missing_identity=RECIPIENT_IDENTITY_NOT_FOUND, busy=RESOLVER_BUSY
)


class AuthorityResultState(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"


class EvidenceCacheUse(Enum):
    NORMAL = auto()
    BYPASS = auto()

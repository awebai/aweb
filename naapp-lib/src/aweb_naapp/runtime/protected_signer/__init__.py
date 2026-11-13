"""Shared typed protected signer; no raw-byte/key-export interface."""

from aweb_naapp.runtime.passkeys.proof import ProtectedKeyContext

from .http import ProtectedOperationsHTTP
from .service import POLICY_REF, ProtectedSigner
from .types import (
    AdmittedHuman,
    AuthorityProvider,
    CatalogOperation,
    ControllerCustody,
    CurrentAuthority,
    OperationReceipt,
    OwnerActOperation,
    PreparedOperation,
    ReceiptReader,
    RestrictedRequester,
    RevokeHumanRole,
    SignerRefused,
    VerifiedProtectedEffect,
)

__all__ = [
    "AdmittedHuman",
    "AuthorityProvider",
    "ControllerCustody",
    "CurrentAuthority",
    "CatalogOperation",
    "OperationReceipt",
    "OwnerActOperation",
    "POLICY_REF",
    "PreparedOperation",
    "ProtectedKeyContext",
    "ProtectedSigner",
    "ProtectedOperationsHTTP",
    "ReceiptReader",
    "RestrictedRequester",
    "RevokeHumanRole",
    "SignerRefused",
    "VerifiedProtectedEffect",
]

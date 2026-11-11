"""Shared typed protected signer; no raw-byte/key-export interface."""

from aweb_naapp.runtime.passkeys.proof import ProtectedKeyContext

from .service import POLICY_REF, ProtectedSigner
from .types import (
    AdmittedHuman,
    AuthorityProvider,
    ControllerCustody,
    CurrentAuthority,
    OperationReceipt,
    PreparedOperation,
    ReceiptReader,
    RestrictedRequester,
    RevokeHumanRole,
    SignerRefused,
)

__all__ = [
    "AdmittedHuman",
    "AuthorityProvider",
    "ControllerCustody",
    "CurrentAuthority",
    "OperationReceipt",
    "POLICY_REF",
    "PreparedOperation",
    "ProtectedKeyContext",
    "ProtectedSigner",
    "ReceiptReader",
    "RestrictedRequester",
    "RevokeHumanRole",
    "SignerRefused",
]

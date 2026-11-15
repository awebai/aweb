"""Shared typed protected signer; no raw-byte/key-export interface."""

from aweb_naapp.runtime.passkeys.proof import ProtectedKeyContext

from .http import ProtectedOperationsHTTP
from .requester_budget import NOTICE_BUDGET, NOTICE_WINDOW, OPEN_REQUEST_LIMIT
from .retention import EffectConfirmation, FrozenDelivery, RetainedEffect, RetainedEffectCustody
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
    "NOTICE_BUDGET",
    "NOTICE_WINDOW",
    "OPEN_REQUEST_LIMIT",
    "AdmittedHuman",
    "AuthorityProvider",
    "ControllerCustody",
    "EffectConfirmation",
    "FrozenDelivery",
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
    "RetainedEffect",
    "RetainedEffectCustody",
    "RevokeHumanRole",
    "SignerRefused",
    "VerifiedProtectedEffect",
]

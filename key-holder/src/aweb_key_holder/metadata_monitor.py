"""Private holder check of active credentials against verified FIDO metadata."""

import hashlib
import json
import sqlite3
from datetime import UTC, datetime

import httpx
from approval_service.encoding import decode
from approval_service.metadata import metadata_health
from approval_service.metadata_cache import fetch_and_pin

from .keys import KeyStore, Refused


def check_metadata(state, *, cache_dir, manifest_path):
    now = datetime.now(UTC)
    try:
        manifest = (
            json.loads(manifest_path.read_text()) if manifest_path is not None else None
        )
        if manifest_path is not None and not isinstance(manifest, dict):
            raise ValueError("invalid metadata manifest")
        store = KeyStore.open(state)
        snapshot = fetch_and_pin(cache_dir, manifest=manifest, now=now)
        report = metadata_health(snapshot, now=now)
        with store._connection() as db:
            rows = db.execute(
                "SELECT assessment FROM active_attestation_inventory "
                "WHERE namespace = (SELECT organisation FROM configuration)"
            )
            affected = any(
                _matches(snapshot, json.loads(row["assessment"]), now=now)
                for row in rows
            )
    except (
        httpx.HTTPError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        sqlite3.Error,
    ) as exc:
        raise Refused("metadata_check_unavailable") from exc
    report["withdrawal"] = "fido_withdrawal_matches_inventory" if affected else None
    if affected:
        report["message"] = (
            "Pause affected hardware-required effects and review the issuer's "
            "private inventory for withdrawal or replacement."
        )
        return report, 3
    return report, 2 if report["warning"] is not None else 0


def _matches(snapshot, assessment, *, now):
    if not isinstance(assessment, dict) or not isinstance(
        assessment.get("format"), str
    ):
        raise TypeError("invalid attestation assessment")
    if "verified_chain" not in assessment:
        return False
    chain = assessment["verified_chain"]
    if not isinstance(chain, list) or not chain:
        raise ValueError("invalid attestation chain")
    aaguid = assessment.get("aaguid")
    if not isinstance(aaguid, str):
        raise TypeError("invalid attestation AAGUID")
    return snapshot.has_effective_withdrawal(
        aaguid,
        now=now,
        certificate_hashes={hashlib.sha256(decode(cert)).digest() for cert in chain},
    )

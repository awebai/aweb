#!/usr/bin/env python3
"""Run with ykman script: sign a bounded release statement using PIV slot 9c."""

import argparse
from getpass import getpass
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from ykman.device import list_all_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.piv import KEY_TYPE, PIN_POLICY, SLOT, TOUCH_POLICY, PivSession

# ykman script supplies sys.argv but does not add the script directory to sys.path.
sys.path.insert(0, str(Path(sys.argv[0]).resolve().parent))
from release_manifest import parse_statement, verify_statement_signature  # noqa: E402


def sign_statement(*, serial, public_key_path, statement_path, signature_path):
    """Implement docs/install-integrity.md:28-39 and :46-52."""
    statement = statement_path.read_bytes()
    parse_statement(statement)
    public = serialization.load_pem_public_key(public_key_path.read_bytes())
    if KEY_TYPE.from_public_key(public) is not KEY_TYPE.ED25519:
        raise ValueError("expected an Ed25519 public key")
    if signature_path.exists():
        raise FileExistsError(f"{signature_path} exists; choose a new output file")
    devices = [device for device, info in list_all_devices() if info.serial == serial]
    if len(devices) != 1:
        raise ValueError("expected exactly one device with the requested serial")
    with devices[0].open_connection(SmartCardConnection) as connection:
        session = PivSession(connection)
        if session.version < (5, 7, 0):
            raise ValueError("release signing requires firmware 5.7 or later")
        metadata = session.get_slot_metadata(SLOT.SIGNATURE)
        if (
            metadata.key_type is not KEY_TYPE.ED25519
            or not metadata.generated
            or metadata.pin_policy is not PIN_POLICY.ALWAYS
            or metadata.touch_policy is not TOUCH_POLICY.ALWAYS
        ):
            raise ValueError("slot 9c must be on-device Ed25519 with PIN/touch ALWAYS")
        if metadata.public_key.public_bytes_raw() != public.public_bytes_raw():
            raise ValueError("slot 9c public key differs from the selected public file")
        print(
            f"Device serial: {serial}; PIV slot 9c; exact statement ({len(statement)} bytes):"
        )
        print(statement.decode("ascii"), end="")
        if (
            input(
                "Compare these lines with the staged release; type SIGN to continue: "
            )
            != "SIGN"
        ):
            raise ValueError("signing cancelled")
        session.verify_pin(getpass("PIV PIN (different from FIDO2/OpenPGP): "))
        print("Touch this YubiKey to sign the displayed statement.", flush=True)
        signature = session.sign(
            slot=SLOT.SIGNATURE,
            key_type=KEY_TYPE.ED25519,
            message=statement,
            hash_algorithm=None,
        )
        verify_statement_signature(
            public=public.public_bytes_raw(), signed=signature, statement=statement
        )
        with signature_path.open("xb") as output:
            output.write(signature)
    print(f"Wrote verified raw Ed25519 signature to {signature_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", type=int, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--statement", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    args = parser.parse_args()
    sign_statement(
        serial=args.serial,
        public_key_path=args.public_key,
        statement_path=args.statement,
        signature_path=args.signature,
    )


# ykman script executes a namespace without __name__ or __file__.
main()

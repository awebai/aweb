"""Synthetic WebAuthn registrations and assertions for crypto/storage tests."""

import hashlib
import json
import secrets
from base64 import b64encode
from datetime import UTC, datetime, timedelta
from uuid import UUID

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from approval_service.canonical import canonical
from approval_service.encoding import decode, encode
from approval_service.metadata import Snapshot
from approval_service.wire import domain


class Passkey:
    def __init__(self, origin, rp_id):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.identifier = secrets.token_bytes(32)
        self.origin, self.rp_id = origin, rp_id

    def client_data(self, kind, challenge):
        return json.dumps(
            {
                "type": kind,
                "challenge": encode(challenge),
                "origin": self.origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()

    def register(self, challenge):
        public = self.key.public_key().public_numbers()
        cose = cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: public.x.to_bytes(32), -3: public.y.to_bytes(32)}
        )
        auth = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + b"\x45"
            + bytes(4)
            + bytes(16)
            + len(self.identifier).to_bytes(2)
            + self.identifier
            + cose
        )
        return {
            "id": encode(self.identifier),
            "client_data_json": encode(self.client_data("webauthn.create", challenge)),
            "attestation_object": encode(
                cbor2.dumps({"fmt": "none", "authData": auth, "attStmt": {}})
            ),
        }

    def assert_request(self, request):
        digest = hashlib.sha256(domain("request") + canonical(request)).digest()
        client = self.client_data("webauthn.get", digest)
        auth = hashlib.sha256(self.rp_id.encode()).digest() + b"\x05" + bytes(4)
        signature = self.key.sign(
            auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": encode(self.identifier),
            "client_data_json": encode(client),
            "authenticator_data": encode(auth),
            "signature": encode(signature),
        }


def packed_device(origin, rp_id):
    """A signed synthetic batch registration and its trusted test snapshot."""
    clock = datetime.now(UTC)
    root_key = ec.generate_private_key(ec.SECP256R1())
    batch_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture root")])
    batch_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fixture vendor"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, "Fixture batch"),
        ]
    )

    def certificate(name, key, *, ca):
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(root_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(clock - timedelta(days=1))
            .not_valid_after(clock + timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=ca, path_length=None), critical=True
            )
            .sign(root_key, hashes.SHA256())
            .public_bytes(Encoding.DER)
        )

    root_der = certificate(root_name, root_key, ca=True)
    batch_der = certificate(batch_name, batch_key, ca=False)
    aaguid = "918eba73-5573-4d34-959f-a533849bec09"
    entry = {
        "aaguid": aaguid,
        "metadataStatement": {
            "attestationRootCertificates": [b64encode(root_der).decode("ascii")],
            "attestationTypes": ["basic_full"],
        },
        "statusReports": [{"status": "FIDO_CERTIFIED_L1"}],
    }
    cutoff = clock + timedelta(hours=1)
    snapshot = Snapshot("1" * 64, 1, cutoff, (entry,), {aaguid: entry}, cutoff)

    class Device(Passkey):
        def register(self, challenge):
            response = super().register(challenge)
            obj = cbor2.loads(decode(response["attestation_object"]))
            auth = obj["authData"][:37] + UUID(aaguid).bytes + obj["authData"][53:]
            signature = batch_key.sign(
                auth + hashlib.sha256(decode(response["client_data_json"])).digest(),
                ec.ECDSA(hashes.SHA256()),
            )
            response["attestation_object"] = encode(
                cbor2.dumps(
                    {
                        "fmt": "packed",
                        "authData": auth,
                        "attStmt": {"alg": -7, "sig": signature, "x5c": [batch_der]},
                    }
                )
            )
            return response

    return Device(origin, rp_id), snapshot, (aaguid, batch_der, root_der)

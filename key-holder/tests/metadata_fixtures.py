"""Signed synthetic MDS cache for the real holder loader tests."""

import json
from base64 import b64encode
from datetime import timedelta
from hashlib import sha256

from approval_service.encoding import encode
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def signed_cache(cache, manifest, *, entry, now, next_update):
    """Write pinned, synthetic artifacts to a private cache and return the blob path."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test MDS root")])

    def certificate(name, key, *, ca):
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(root_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=7))
            .add_extension(
                x509.BasicConstraints(ca=ca, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=not ca,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=ca,
                    crl_sign=ca,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )
        if not ca:
            builder = (
                builder.add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        root_key.public_key()
                    ),
                    critical=False,
                )
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("mds.fidoalliance.org")]),
                    critical=False,
                )
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                    critical=False,
                )
            )
        return builder.sign(root_key, hashes.SHA256()).public_bytes(Encoding.DER)

    root = certificate(root_name, root_key, ca=True)
    signer_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Test MDS signer")]
    )
    signer = certificate(signer_name, signer_key, ca=False)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_name)
        .last_update(now - timedelta(days=1))
        .next_update(now + timedelta(days=3))
        .sign(root_key, hashes.SHA256())
        .public_bytes(Encoding.DER)
    )
    header = {"alg": "RS256", "x5c": [b64encode(signer).decode("ascii")]}
    payload = {
        "no": 1,
        "nextUpdate": next_update.date().isoformat(),
        "entries": [entry],
    }
    preimage = ".".join(
        encode(json.dumps(value).encode()) for value in (header, payload)
    )
    signature = signer_key.sign(preimage.encode(), padding.PKCS1v15(), hashes.SHA256())
    blob = f"{preimage}.{encode(signature)}".encode()
    cache.mkdir(mode=0o700)

    def pin(raw):
        digest = sha256(raw).hexdigest()
        artifact = cache / f"{digest}.artifact"
        artifact.write_bytes(raw)
        artifact.chmod(0o600)
        return {
            "sha256": digest,
            "url": "https://no-network.invalid/blob",
            "max_bytes": 1048576,
        }

    blob_pin = pin(blob)
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "minimum_sequence": 1,
                "artifacts": {"blob": blob_pin, "root": pin(root), "crls": [pin(crl)]},
            }
        )
    )
    return cache / f"{blob_pin['sha256']}.artifact"

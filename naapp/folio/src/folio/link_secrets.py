"""Folio stores a presentation-link secret only as its verifier.

Rules implemented here: docs/sot.md §6 (an editable link's opener and session
credential are stored only as SHA-256) and §7, Storage (a read-only link's row
is keyed by its token's verifier).

The verifier is naapp-lib's ``secret_verifier``, the SHA-256 of the secret's
UTF-8 bytes, so a database read never yields a value that opens a link. A
read-only link's row is keyed by the hex verifier of its bearer token; an
editable link's opener and its edit-session credentials store the 32 bytes.
"""

from aweb_naapp.runtime.link_requests import secret_verifier


def read_only_link_key(token: str) -> str:
    """The row key of a read-only link: the hex verifier of its bearer token."""
    return secret_verifier(token)


def secret_digest(secret: str) -> bytes:
    """The stored form of an editable link's opener or an edit-session credential."""
    return bytes.fromhex(secret_verifier(secret))

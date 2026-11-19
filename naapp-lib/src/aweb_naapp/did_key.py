"""The length bound of an Ed25519 did:key, for code that must not decode one.

Standard library only: the manifest loader and the secrets runner refuse a
did:key on its length before anything base58-decodes it.
"""

from __future__ import annotations

# The most base58 characters the 34 bytes of an Ed25519 did:key (multicodec
# 0xed01 and the 32-byte key) encode to. Longer text is refused before the
# base58 decode, whose cost grows with the square of the input length.
DID_KEY_ENCODED_MAX = 47

"""aweb coordination server."""

from awid import signing as _awid_signing

if not callable(getattr(_awid_signing, "validate_message_via", None)):
    raise ImportError(
        "aweb signed via requires awid-service>=0.5.34rc1 "
        "with awid.signing.validate_message_via; upgrade awid-service."
    )

del _awid_signing

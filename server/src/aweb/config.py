import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from awid.did import did_from_public_key, public_key_from_did
from awid.dns_verify import DEFAULT_AWID_REGISTRY_URL
from awid.log import canonical_server_origin
from awid.ratelimit import normalize_service_token
from awid.utc_timestamps import parse_utc_seconds


def _env_bool(*names: str, default: bool = False) -> bool:
    for name in names:
        value = os.getenv(name)
        if value is None:
            continue
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return default


def _env_optional_int(*names: str) -> Optional[int]:
    for name in names:
        value = os.getenv(name)
        if value is None or not value.strip():
            continue
        return int(value)
    return None


@dataclass
class Settings:
    host: str
    port: int
    log_level: str
    reload: bool
    redis_url: str
    database_url: str
    database_uses_transaction_pooler: bool
    database_statement_cache_size: Optional[int]
    presence_ttl_seconds: int
    awid_registry_url: str
    awid_service_token: str
    public_origin: str
    dashboard_jwt_secret: str
    require_registered_certificates: bool
    app_grant_max_age_seconds: int
    hook_producer_keys: tuple["HookProducerKey", ...]


def get_awid_registry_url() -> str:
    value = (os.getenv("AWID_REGISTRY_URL") or "").strip()
    if not value:
        return DEFAULT_AWID_REGISTRY_URL
    if value.lower() == "local":
        raise ValueError(
            "AWID_REGISTRY_URL=local is no longer supported. Run the awid service separately and point AWEB at its HTTP origin."
        )
    return value


def get_awid_service_token() -> str:
    token = normalize_service_token(os.getenv("AWID_SERVICE_TOKEN"))
    if token is None:
        raise ValueError(
            "AWID_SERVICE_TOKEN is required so aweb can verify private-team "
            "certificates through AWID. Generate one with `openssl rand -hex 32`, "
            "configure the same value on aweb and AWID, and restart both services."
        )
    return token


def require_registered_certificates() -> bool:
    """Staged existence-required certificate verification (hosted anchoring).

    Controlled by ``AWEB_REQUIRE_REGISTERED_CERTIFICATES`` (default OFF).

    When ON, a team certificate that passes signature and revocation checks
    must ALSO exist at the AWID registry: an unregistered certificate is
    unrevocable (the revocation check can never name it), so once the hosted
    anchoring backfill has run, "not registered" becomes a verification
    failure rather than a pass-by-omission.

    Activation contract (docs/drafts/hosted-certificate-anchoring.md):
    this flag may be enabled only once the anchoring backfill's failure
    enumeration is EMPTY or every enumerated failure has an individual
    remediation completed (the emptiness gate). Unregistered-certificate
    gaps that do not self-heal escalate within the operational bound of
    three consecutive failed reconciliation cycles or 24 hours, whichever
    comes first. Flipping this ON in production is an ops act gated on the
    backfill report — enabling it before backfill locks out every
    pre-anchoring hosted member.

    Read from the environment at call time (like the rest of the settings)
    so the OFF path costs nothing and tests can toggle it per-case.
    """
    return _env_bool("AWEB_REQUIRE_REGISTERED_CERTIFICATES")


def get_public_origin() -> str:
    """Resolve only the public endpoint, without loading infrastructure settings."""
    return canonical_server_origin(
        os.getenv("AWEB_PUBLIC_ORIGIN") or f"http://localhost:{int(os.getenv('AWEB_PORT', '8000'))}"
    )


APP_GRANT_MAX_AGE_CEILING_SECONDS = 60
_POSITIVE_DECIMAL = re.compile(r"[1-9][0-9]*")


def get_app_grant_max_age_seconds() -> int:
    """How long an app may reuse a grant answer, from ``AWEB_APP_GRANT_MAX_AGE_SECONDS``.

    Default and ceiling are 60 seconds. It is also the staleness bound that
    hook activation pads with, so a value outside 1..60 is refused rather
    than clamped.
    """
    value = os.getenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", str(APP_GRANT_MAX_AGE_CEILING_SECONDS))
    if not _POSITIVE_DECIMAL.fullmatch(value) or int(value) > APP_GRANT_MAX_AGE_CEILING_SECONDS:
        raise ValueError(
            f"AWEB_APP_GRANT_MAX_AGE_SECONDS must be a whole number of seconds from 1 to "
            f"{APP_GRANT_MAX_AGE_CEILING_SECONDS}, got {value!r}"
        )
    return int(value)


# A kid as hook events carry it (the hook event envelope's kid rule).
_HOOK_KID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_HOOK_PRODUCER_KEY_FIELDS = frozenset({"kid", "did_key", "valid_from", "valid_until"})


@dataclass(frozen=True)
class HookProducerKey:
    """A public key the core hook producer signs or signed events with.

    ``valid_until`` is None while the key has no end; retired keys stay listed
    so events they signed keep verifying."""

    kid: str
    did_key: str
    valid_from: str
    valid_until: str | None


def get_hook_producer_keys() -> tuple[HookProducerKey, ...]:
    """The core hook producer's public keys, from ``AWEB_HOOK_PRODUCER_KEYS``.

    The value is a JSON list of ``{kid, did_key, valid_from, valid_until}``,
    times as ``YYYY-MM-DDTHH:MM:SSZ`` and ``valid_until`` null for a key with no
    end. Unset means no keys. Anything malformed is refused, so the server does
    not start with a key list consumers would read differently.
    """
    raw = os.getenv("AWEB_HOOK_PRODUCER_KEYS")
    if raw is None or not raw.strip():
        return ()
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("AWEB_HOOK_PRODUCER_KEYS must be a JSON list") from exc
    if not isinstance(entries, list):
        raise ValueError("AWEB_HOOK_PRODUCER_KEYS must be a JSON list")
    keys = tuple(_hook_producer_key(entry) for entry in entries)
    kids = [key.kid for key in keys]
    if len(set(kids)) != len(kids):
        raise ValueError("AWEB_HOOK_PRODUCER_KEYS lists a kid more than once")
    return keys


def get_hook_signing_key_file() -> tuple[str, str] | None:
    """Dedicated core hook key, selected by kid from the public key list."""
    kid = os.getenv("AWEB_HOOK_PRODUCER_KID", "").strip()
    path = os.getenv("AWEB_HOOK_PRODUCER_KEY_FILE", "").strip()
    if not kid and not path:
        return None
    if not kid or not path or not _HOOK_KID.fullmatch(kid):
        raise ValueError("AWEB_HOOK_PRODUCER_KID and AWEB_HOOK_PRODUCER_KEY_FILE must be configured together")
    return kid, path


def _hook_producer_key(entry: object) -> HookProducerKey:
    if not isinstance(entry, dict) or set(entry) != _HOOK_PRODUCER_KEY_FIELDS:
        raise ValueError(
            "each AWEB_HOOK_PRODUCER_KEYS entry has exactly kid, did_key, valid_from and valid_until"
        )
    kid, did_key, valid_from, valid_until = (
        entry["kid"],
        entry["did_key"],
        entry["valid_from"],
        entry["valid_until"],
    )
    if not isinstance(kid, str) or not _HOOK_KID.fullmatch(kid):
        raise ValueError(f"AWEB_HOOK_PRODUCER_KEYS: invalid kid {kid!r}")
    if not isinstance(did_key, str) or not _is_ed25519_did_key(did_key):
        raise ValueError(f"AWEB_HOOK_PRODUCER_KEYS: kid {kid} has an invalid did_key")
    starts = _key_time(kid, "valid_from", valid_from)
    if valid_until is not None and _key_time(kid, "valid_until", valid_until) <= starts:
        raise ValueError(f"AWEB_HOOK_PRODUCER_KEYS: kid {kid} ends before it starts")
    return HookProducerKey(kid=kid, did_key=did_key, valid_from=valid_from, valid_until=valid_until)


def _is_ed25519_did_key(value: str) -> bool:
    try:
        return did_from_public_key(public_key_from_did(value)) == value
    except ValueError:
        return False


def _key_time(kid: str, name: str, value: object) -> datetime:
    try:
        return parse_utc_seconds(value)
    except ValueError as exc:
        raise ValueError(
            f"AWEB_HOOK_PRODUCER_KEYS: kid {kid} {name} must be YYYY-MM-DDTHH:MM:SSZ"
        ) from exc


def get_settings() -> Settings:
    """
    Load settings from environment at call time.

    Uses `AWEB_*` settings, falling back to unprefixed infrastructure vars where
    that keeps deployment wiring simple.
    """
    database_url = os.getenv("AWEB_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not database_url:
        raise ValueError(
            "DATABASE_URL or AWEB_DATABASE_URL environment variable is required. "
            "Example: postgresql://user:pass@localhost:5432/aweb"
        )

    redis_url = os.getenv("AWEB_REDIS_URL") or os.getenv("REDIS_URL") or "redis://localhost:6379/0"

    port_str = os.getenv("AWEB_PORT", "8000")
    try:
        port = int(port_str)
        if not 1 <= port <= 65535:
            raise ValueError(f"AWEB_PORT must be between 1 and 65535, got {port}")
    except ValueError as e:
        if "invalid literal" in str(e):
            raise ValueError(f"AWEB_PORT must be a valid integer, got '{port_str}'")
        raise

    presence_ttl_str = os.getenv("AWEB_PRESENCE_TTL_SECONDS", "1800")
    try:
        presence_ttl = int(presence_ttl_str)
        if presence_ttl < 10:
            raise ValueError("AWEB_PRESENCE_TTL_SECONDS must be at least 10")
    except ValueError as e:
        if "invalid literal" in str(e):
            raise ValueError(
                f"AWEB_PRESENCE_TTL_SECONDS must be a valid integer, got '{presence_ttl_str}'"
            )
        raise

    return Settings(
        host=os.getenv("AWEB_HOST", "0.0.0.0"),
        port=port,
        log_level=os.getenv("AWEB_LOG_LEVEL", "info"),
        reload=os.getenv("AWEB_RELOAD", "false").lower() == "true",
        redis_url=redis_url,
        database_url=database_url,
        database_uses_transaction_pooler=_env_bool(
            "AWEB_DATABASE_USES_TRANSACTION_POOLER",
            "DATABASE_USES_TRANSACTION_POOLER",
        ),
        database_statement_cache_size=_env_optional_int(
            "AWEB_DATABASE_STATEMENT_CACHE_SIZE",
            "DATABASE_STATEMENT_CACHE_SIZE",
        ),
        presence_ttl_seconds=presence_ttl,
        awid_registry_url=get_awid_registry_url(),
        awid_service_token=get_awid_service_token(),
        public_origin=get_public_origin(),
        dashboard_jwt_secret=os.getenv("AWEB_DASHBOARD_JWT_SECRET", ""),
        require_registered_certificates=require_registered_certificates(),
        app_grant_max_age_seconds=get_app_grant_max_age_seconds(),
        hook_producer_keys=get_hook_producer_keys(),
    )

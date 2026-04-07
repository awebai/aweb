# awid Package Migration

This document maps modules and symbols that moved out of `aweb` and into the
new top-level `awid` package (a sibling of `awid_service` in the `awid/` repo
folder). After this refactor:

- `awid_service` and `aweb` both depend on the shared `awid` package
- `awid_service` has zero imports from `aweb`
- The `awid/` repo folder ships two distributions in one wheel: `awid` (shared
  primitives) and `awid_service` (the registry HTTP service)

## Module mapping

| Old (aweb)                           | New (awid)             | Notes                                                                  |
|--------------------------------------|------------------------|------------------------------------------------------------------------|
| `aweb.awid` (subpackage)             | `awid` (top-level)     | The whole `aweb/awid/` subpackage was promoted                         |
| `aweb.awid.contract`                 | `awid.contract`        | identity contract types                                                |
| `aweb.awid.did`                      | `awid.did`             | DID encoding / keypair generation                                      |
| `aweb.awid.log`                      | `awid.log`             | identity audit log helpers                                             |
| `aweb.awid.registry`                 | `awid.registry`        | `RegistryClient`, `CachedRegistryClient`, error types                  |
| `aweb.awid.signing`                  | `awid.signing`         | Ed25519 + canonical JSON                                               |
| `aweb.db_config`                     | `awid.db_config`       | pgdbm config builder                                                   |
| `aweb.dns_verify`                    | `awid.dns_verify`      | DNS TXT verification + `DomainAuthority` / `DomainVerifier`            |
| `aweb.logging`                       | `awid.log_config`      | **renamed** to avoid shadowing the stdlib `logging` module             |
| `aweb.pagination`                    | `awid.pagination`      | cursor encoding + `validate_pagination_params`                         |
| `aweb.ratelimit`                     | `awid.ratelimit`       | rate limiter + FastAPI dependency helpers                              |
| `aweb.routes.dns_auth`               | `awid.dns_auth`        | DIDKey signature parsing/verification helpers                          |

## Symbol cheat sheet

### `awid.did`
`generate_keypair`, `did_from_public_key`, `public_key_from_did`,
`validate_did`, `encode_public_key`, `decode_public_key`,
`stable_id_from_public_key`, `stable_id_from_did_key`, `validate_stable_id`

### `awid.signing`
`canonical_json_bytes`, `canonical_payload`, `sign_message`,
`verify_signature_with_public_key`, `verify_signature`,
`verify_did_key_signature`, `VerifyResult`

### `awid.registry`
`RegistryClient`, `CachedRegistryClient`, `RegistryError`,
`AlreadyRegisteredError`, `DIDMapping`, `KeyResolution`, `Namespace`,
`Address`, `DIDKeyEvidence`

### `awid.contract`
`ResolvedIdentityContract`, `resolve_identity_contract`,
`assert_permanent_identity`

### `awid.dns_verify`
`DomainAuthority`, `DomainVerifier`, `DnsVerificationError`, `verify_domain`,
`discover_authoritative_registry`, `discover_registry_override`,
`awid_txt_name`, `awid_txt_value`, `DEFAULT_AWID_REGISTRY_URL`

### `awid.dns_auth`
`parse_didkey_auth`, `require_timestamp`, `enforce_timestamp_skew`,
`verify_signed_json_request`, `validate_did_key`

### `awid.log`
`sha256_hex`, `canonical_server_origin`, `require_canonical_server_origin`,
`log_entry_payload`, `state_hash`

### `awid.log_config`
`JSONFormatter`, `configure_logging`

### `awid.pagination`
`PaginatedResponse`, `encode_cursor`, `decode_cursor`,
`validate_pagination_params`

### `awid.ratelimit`
`RateLimiter`, `MemoryFixedWindowRateLimiter`, `RedisFixedWindowRateLimiter`,
`RateLimitDecision`, `build_rate_limiter`, `ip_bucket_key`,
`get_rate_limiter`, `enforce_rate_limit`, `rate_limit_dep`

### `awid.db_config`
`build_database_config`

## Imports that did **not** move

These remain in `aweb` because they are coordination-specific:

- `aweb.config` — including `DEFAULT_AWID_REGISTRY_URL` (a server-side setting
  that wraps the constant from `awid.dns_verify`)
- `aweb.team_auth`, `aweb.team_auth_deps` — team certificate verification on
  the aweb side
- everything under `aweb.coordination`, `aweb.messaging`, `aweb.routes`

## Packaging

`awid/pyproject.toml`:

```toml
[project]
name = "awid-service"

[tool.hatch.build.targets.wheel]
packages = ["src/awid", "src/awid_service"]
```

The `awid-service` distribution now contains both Python packages. Consumers
that only need the shared primitives still install `awid-service` and import
from `awid`.

`server/pyproject.toml` declares `awid-service` as a dependency and (in the
monorepo) sources it from `../awid` via `[tool.uv.sources]`.

## Migration recipe for downstream code

For each affected import:

1. Replace the module prefix per the table above
2. If you imported from `aweb.logging`, switch to `awid.log_config`
3. If you imported from `aweb.routes.dns_auth`, switch to `awid.dns_auth`
4. Symbols whose names did not change keep the same name on the new module

Example:

```python
# before
from aweb.awid.signing import canonical_json_bytes, sign_message
from aweb.awid.did import did_from_public_key, generate_keypair
from aweb.awid.registry import RegistryClient, AlreadyRegisteredError
from aweb.dns_verify import DomainAuthority, verify_domain
from aweb.logging import configure_logging
from aweb.routes.dns_auth import parse_didkey_auth, require_timestamp

# after
from awid.signing import canonical_json_bytes, sign_message
from awid.did import did_from_public_key, generate_keypair
from awid.registry import RegistryClient, AlreadyRegisteredError
from awid.dns_verify import DomainAuthority, verify_domain
from awid.log_config import configure_logging
from awid.dns_auth import parse_didkey_auth, require_timestamp
```

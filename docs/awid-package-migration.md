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

## Behavior and signature changes

No moved function changed its signature, return type, exceptions, or runtime
behavior. **Every move was a relocation only.** The differences a downstream
consumer will see are entirely about *where* to import from.

That said, four things are not pure renames and need attention:

### 1. `awid` package root no longer re-exports submodule symbols (BREAKING)

The old `aweb.awid/__init__.py` re-exported 22 symbols at the package root,
so callers could write:

```python
from aweb.awid import canonical_json_bytes, RegistryClient, generate_keypair
```

The new `awid/__init__.py` is intentionally empty (docstring only). The
following will **not** work:

```python
from awid import canonical_json_bytes  # ImportError
```

You must import from the specific submodule:

```python
from awid.signing import canonical_json_bytes
from awid.registry import RegistryClient
from awid.did import generate_keypair
```

The "Symbol cheat sheet" above tells you which submodule each name lives in.

### 2. `DEFAULT_AWID_REGISTRY_URL` moved out of `aweb.config`

Was: `from aweb.config import DEFAULT_AWID_REGISTRY_URL`
Is:  `from awid.dns_verify import DEFAULT_AWID_REGISTRY_URL`

`aweb.config` still re-exports the same name from `awid.dns_verify`, so
existing `from aweb.config import DEFAULT_AWID_REGISTRY_URL` continues to
work — but new code should import from `awid.dns_verify` directly so the
constant is sourced from one place.

### 3. New `DomainVerifier` type alias in `awid.dns_verify`

```python
from typing import Awaitable, Callable

DomainVerifier = Callable[[str], Awaitable["DomainAuthority"]]
```

This is the canonical type for any function that takes a domain name and
returns a `DomainAuthority`. Use it in test fakes and dependency-injection
overrides instead of redeclaring the signature.

### 4. New `awid_service.deps` module (FastAPI dependencies)

`awid_service` now exposes three dependencies in `awid_service.deps`:

- `get_db(request) -> Any` — returns `request.app.state.db`
- `get_redis(request) -> Any` — returns `request.app.state.redis`
- `get_domain_verifier() -> DomainVerifier` — returns the real `verify_domain`

Tests override the verifier the FastAPI way:

```python
from awid_service.deps import get_domain_verifier
app.dependency_overrides[get_domain_verifier] = lambda: my_fake_verifier
```

Routes that previously imported `verify_domain` directly from
`awid.dns_verify` should now `Depends(get_domain_verifier)` so they can be
faked in tests.

## Migration recipe for downstream code

For each affected import:

1. Replace the module prefix per the table above
2. If you imported from `aweb.logging`, switch to `awid.log_config`
3. If you imported from `aweb.routes.dns_auth`, switch to `awid.dns_auth`
4. If you imported from `aweb.awid` (the package root, not a submodule),
   switch to the specific submodule — see Behavior change #1 above
5. Symbols whose names did not change keep the same name on the new module

Example:

```python
# before
from aweb.awid import canonical_json_bytes, RegistryClient  # package root
from aweb.awid.signing import sign_message
from aweb.awid.did import did_from_public_key, generate_keypair
from aweb.awid.registry import AlreadyRegisteredError
from aweb.dns_verify import DomainAuthority, verify_domain
from aweb.logging import configure_logging
from aweb.routes.dns_auth import parse_didkey_auth, require_timestamp
from aweb.config import DEFAULT_AWID_REGISTRY_URL

# after
from awid.signing import canonical_json_bytes, sign_message
from awid.registry import RegistryClient, AlreadyRegisteredError
from awid.did import did_from_public_key, generate_keypair
from awid.dns_verify import DomainAuthority, verify_domain, DEFAULT_AWID_REGISTRY_URL
from awid.log_config import configure_logging
from awid.dns_auth import parse_didkey_auth, require_timestamp
```

# Pre-activation federation harness fixtures

`preactivation-harness-v1.json` inventories all 51 rows of the reviewed
`aweb-aazd.2.1` conformance matrix without activating federation ingress.

Every row has one of two modes:

- `direct_core` — executed against the landed inactive strict-authority APIs,
  deterministic DNS/HTTP/TLS fixtures, and real PostgreSQL shared by workers.
- `activation_fixture` — canonical plaintext/encrypted/replay input and expected
  contract provenance owned by `aweb-aazd.6`; schema-complete plaintext and
  encrypted requests are validated by the production request model, but no row
  is reported as executed runtime behavior.

The disposable real-stack gate starts AWID-A and AWID-B plus two aweb receiver
services, each with two processes sharing that side's PostgreSQL state. Runtime
certificates and keys live only in a temporary directory. The harness never
calls strict federation ingress. Cross-process barriers prove one real shared
resolution chain, the exact 32/2/4 PostgreSQL permit ceilings, atomic failure,
and the shared token bucket. Outage and blocked-lock timeout paths fail closed.
The gate verifies `docker compose down -v` leaves no project containers or
volumes.

Validate the inventory and killing mutations with:

```text
make test-federation-harness
```

Run the disposable topology and existing compatibility journey with:

```text
make test-federation-e2e
```

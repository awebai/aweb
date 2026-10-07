# Deployed manifest and event contract fixtures

These JSON files are exact raw deployed manifest bytes, not reserialized models:

- `folio-deployed.json`: awebai/folio commit `bea8052c677e07565798c0de0580039b18df008a`, `src/folio/aweb-app.json`; SHA-256 `480b157753e1ecc9cd257daf70a35b97c5943960d69183971c32498b48c313e3`.
- `library-deployed.json`: awebai/library commit `565d1e69bd8fee27ba99f374141e1b74e3d8cbf0`, `src/library/aweb-app.json`; SHA-256 `0019130d90bbbc61fde49c144b4f883eabac837889b0c69f515d206b35552329`.

The app owner independently matched both hashes to the live public manifest on
2026-10-07. Folio declares events; the deployed Library manifest does not.
`TestDeployedManifestContracts` checks the hashes before strict decoding.
The binary installation fixture serves these bytes unchanged on loopback and
uses the existing explicit `--dev-origin` option to route calls to the fixture.
That option re-encodes the installed copy with a loopback origin; it must retain
event metadata. All 37 declared verbs are exercised, with signed calls checked
against the synthetic resident certificate and team-auth v2 request binding.
These are client compatibility tests, not deployed application business tests.

`events-v1.json` is the shared event-declaration contract matrix. The Go test
requires `accepted`; the pinned Cloud excerpt runner at
`scripts/check-app-event-vectors.py` requires `gateway_accepted`. Differences
are deliberately recorded for old gateway coercions and its missing count
bound. Well-formed and exact deployed-manifest cases agree. The excerpt has no
runtime authority and does not change Cloud. The strict contract allows at most
64 declarations, optional string description (4096 trimmed Unicode characters),
app-local type, and exact ambient/wake/steer intent (absent defaults to ambient).

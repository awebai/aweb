# App manifest fixture vectors

This directory stores digest-pinned raw app manifest byte snapshots used by the
shared manifest interpretation harness.

Fixture rules:

- manifests are committed as the exact raw bytes an app serves from
  `/.well-known/aweb-app.json`;
- bytes are canonical JSON: sorted keys, no insignificant whitespace, UTF-8, LF;
- `app-manifest-fixtures-v1.json` pins each fixture by SHA-256 and lists offline
  interpretation cases;
- tests assert raw bytes -> SHA-256 before JSON parsing, so consumers do not
  accidentally validate a re-serialized dictionary.

For the live folio m2.2 proof, the integration check should assert:

`GET <origin>/.well-known/aweb-app.json bytes == vendored fixture bytes == sha256`

The conformance suite itself stays offline and self-contained; it must not read
from the folio repository.

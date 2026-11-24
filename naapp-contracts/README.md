# aweb-naapp-contracts

The contracts between aweb and its Native Agentic Apps (naapps), as one small
package that the aweb server, the `aw` CLI's conformance tests and every naapp
share:

- `aweb_naapp_contracts.manifest` and `manifest_keys`: reading and checking an
  app's `aweb-app.json` manifest ([app manifest](../docs/app-manifest.md)).
- `aweb_naapp_contracts.egress` (extra `egress`): the egress guard for calls to
  external services.
- `aweb_naapp_contracts.hooks` (extra `hooks`): the hook catalog, the event
  envelope, the delivery credential, and owner acts with their nonce table
  ([hook events](../docs/hook-events.md), [owner acts](../docs/owner-act.md)).
- `aweb_naapp_contracts.task_requests` (extra `hooks`): the member's task
  authorization, stage receipts and answer digests
  ([app task requests](../docs/app-task-requests.md)).
- `client_identity`, `did_key`, `key_file`: the small helpers they share.

```bash
uv add "aweb-naapp-contracts[egress,hooks]"
```

The naapp runtime and the apps are published from the naapp repository and
depend on this package.

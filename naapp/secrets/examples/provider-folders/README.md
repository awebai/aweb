# Provider folders: publishing one report to a OneDrive app folder

This example implements the publisher side of `aweb-acwd.25.1`. An agent
exports a report to its seat's outbox. A publisher job, under its own identity,
uploads that report at most once to the OneDrive folder its token can reach.
Providers are reached by API calls, not through a mount. The token's scope comes
from the provider, so a mount adds no boundary, and the API calls expose what
idempotency needs: item IDs, `conflictBehavior=fail`, and provider content
hashes.

The fixtures here exercise the publisher's own handling against a local
stand-in for Microsoft Graph. They do not qualify real access, scope, account
support or provider refusals, and they do not prove that Secrets recovers an
interrupted runner job.

## Hand-off contract

- **Submit (agent, `submit.py`).** The agent keeps its durable work and the
  report source in `/state`. It exports to `/outbox`, a setgid `2750` directory
  owned by the agent UID whose group is the publisher's only read grant. The
  helper writes `<job_id>.<ext>`, then `<job_id>.json` (`job_id`, `file`,
  `size`, `sha256`, `target`), both `0640` whatever the umask. The manifest
  appears last, by a no-replace link: its existence is the submit, and a queued
  job is never replaced. The helper refuses an outbox or a file that the
  publisher's group could not read.
- **Fetch (publisher, `publisher.py`).** The outbox is untrusted. The manifest
  is bounded at 4 KiB, with exact fields, and `target` is a leaf name. The
  report is opened by leaf name relative to the outbox without following links,
  must be a regular file, and is read with the byte cap enforced. The publisher
  checks its size and SHA-256 and uploads exactly the verified bytes it holds in
  memory, so a later change to the outbox file cannot reach the upload. No copy
  of a report is kept in publisher state; a retry re-reads and re-verifies the
  outbox file against the manifest. Operator configuration, never the manifest, fixes the
  seat, the size limit (20 MiB in the initial run) and the extensions (`pdf`,
  `docx`, `md`, `txt`). An extension allowlist is not a content-safety check.
- **Identity.** A publication is (seat, job_id, sha256, target) at one
  destination. The publisher records it in its ledger before any provider write,
  and the upload writes it onto the item itself:
  `description = "aweb-publish/1 seat=<seat> job=<job_id> sha256=<sha256>"`.
  A reused job_id with any other binding is a `job_conflict`. A fresh job_id
  from the same seat with the same content and target is a `duplicate`. A
  target that other content occupies is `target_taken`. An item that carries
  this job's binding but whose size or quickXorHash does not verify is
  `remote_unverified`: an item from this job exists and needs a read-back.
- **Write (`onedrive.py`).** The publisher lists the app folder, then creates
  any new item through an upload session whose item body carries
  `@microsoft.graph.conflictBehavior: fail` and the binding `description`, so
  the item and its binding land together. A simple PUT is never used, because
  its default is replace. The bearer token goes only to Graph: never to the
  pre-authenticated upload URL, a redirected download host, or a `nextLink` on
  another origin. Remote content is compared by `quickXorHash`, the only hash
  Graph documents for both personal and business drives. The read-back by item
  ID downloads the bytes and compares SHA-256. `description` is documented for
  OneDrive Personal only. A provider answer that is not the documented shape is
  an unknown outcome (`malformed_response`), reconciled on the next run like a
  lost answer.
- **Receipts.** Each outcome (`published`, `already_published`, `refused` with
  a reason) is written under the publisher's state. A lost receipt never repeats
  an upload, because the next run reconciles against the folder.

## Recovery

The OneDrive folder is the authority on what was published. The ledger in the
publisher's own state is a cache.

- **Ledger lost or restored stale.** On the next run, the publisher rebuilds the
  ledger from a listing of the folder before any provider write. For each
  manifest: a job_id found with the same target and content is done, with no
  write; one found with a different binding is a conflict; one not found, with
  the target free, is uploaded with `conflictBehavior=fail`; one not found, with
  the target taken, is refused. A ledger recorded for another destination
  refuses to run (`destination_changed`). A ledger that cannot be read refuses
  to run (`ledger_unreadable`) rather than guess; the operator removes it, and
  the next run rebuilds it from the folder.
- **An interrupted write.** If the provider's answer is lost, the job is marked
  uncertain and stays queued. The next run reconciles the remote item (binding,
  name, size and quickXorHash) before any retry. The result is a verified match
  or an explicit conflict, never a second item or an overwrite, even when the
  ledger was also lost.
- **Queued, unpublished exports.** `/outbox` is outside the `/state` backup, and
  the folder cannot reconstruct a report that was never published. Before a
  cutover, either drain the outbox (replay until every job is published or
  refused, then reconcile), or preserve the outbox's files with their manifests
  and replay after restore. `replay()` reports each job's outcome. An uncertain
  job is reported, left queued, and does not stop the others. A replay against
  a fresh publisher state publishes the queued jobs and leaves the published
  ones untouched.
- **Fencing.** On restore, stop the old publisher and the old agent before the
  replacement runs. The single-writer assumption is the operator's, not this
  code's.

## Limits of the current slice

- No provider token is used. The Microsoft refresh-token custody
  (`oauth2-refresh`) waits for Juan's ruling, and there is no Microsoft token
  step of any kind until then.
- The runner job packaging (the executable entry point, the run configuration
  and the job pin) follows once the runner binding is set. Known open items on
  that path: aweb-acgh.18.52, aweb-acgh.18.15, aweb-acwd.4.6, and the HO6/S19
  dedicated-user evidence.
- Full crash and retry qualification also needs Secrets' reconciliation of
  accepted assignments (aweb-adje.16 11.3).
- Peers sharing one UID remain one trust group. The outbox is a per-seat
  authorization boundary, not an exfiltration boundary.

## Tests

```sh
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

`tests/standin.py` is an in-memory Graph app folder with injected faults: a
response lost after commit, a name created concurrently, a denial, and a
foreign `nextLink`. The quickXorHash implementation is checked against an
independent implementation (`quickxorhash`, test-only).

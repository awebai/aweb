# CLI naapp access

A naapp is a declarative HTTP app described by a v1 app manifest. Install it
once from the identity's own home:

```sh
aw plugin install https://notes.example/.well-known/aweb-app.json
aw notes list
```

Local and global residents use their own selected team's certificate for signed
app requests. An attached resident may use `--identity-home` or
`AWEB_IDENTITY_HOME`; commands never fall back to the instance directory.
Installing from that resident home also approves the app for future grants.
Installing an already installed app records approval for this resident too.

## Discovery and resident approval

Manifests live in the per-OS-user store, `$AW_HOME/plugins` when set, otherwise
`$HOME/.aw/plugins`. Existing installations remain usable. This shared store is
not grant authority. Each resident has a separate `app-approvals.json` in its
identity home, recording app IDs and canonical origins. The catalog starts empty
on upgrade: an existing installation alone does not add authority to a new grant.
A plain non-attached shell without an identity can still install in the host
store, but that operation approves no resident.

`aw plugin list` is discovery, including for grant homes; it does not claim the
listed apps were delegated. `aw plugin update <app>` updates a resident-approved
app only if the fetched ID and origin still match its approval. A changed origin
requires an explicit install to approve it again. Invalid catalogs fail closed; invalid apps are never delegated.

`aw plugin remove <app>` from a resident removes only that resident's approval.
It retains the shared manifest and other residents' approvals. Removal affects
subsequent minting; it does not revoke an existing grant or its snapshot.

Grant homes cannot install, update or remove apps (`app_management_denied`).
Attached executable-plugin management remains refused. Manifest management does
not run hooks or fall back to executable installation, and executable-name
collisions are refused before writes. Released executable dispatch is unchanged.

## Grant snapshots

A normal `aw id grant mint` includes all apps in the selected resident catalog.
Mint checks each current installed manifest's ID and origin against the catalog
and excludes mismatching or unavailable apps from that mint. It snapshots the finite signed tools and their manifest
hash into the resident's grant state. Public (`auth: none`) tools require no
signature and are not included as signing authority. Coordination and registry
origins remain prohibited signing destinations.

Custody signs from that snapshot, not from a worker's manifest. Later worker
edits cannot widen or redirect it. Removing local discovery may make a tool
unavailable, but cannot add authority. Re-minting picks up newly approved apps;
existing grants keep their original snapshots. An app missing from a grant is
refused with `app_tool_denied` before an app HTTP request.

Mint JSON includes `apps`, sorted by app ID, with the actual persisted inventory:

```json
{"apps":[{"app_id":"notes","origin":"https://notes.example","manifest_sha256":"sha256:…","tools":["create","list"]}]}
```

An empty catalog emits `"apps": []`. Tool names are sorted. `skipped_apps` is
always an array of `{app_id, code}` objects. Missing, invalid, ID-mismatched,
origin-mismatched or prohibited-origin apps are excluded and reported as
`app_missing`, `app_manifest_invalid`, `app_manifest_mismatch`,
`app_origin_mismatch` or `app_origin_denied`. Other apps and the grant itself
remain available. A corrupt resident catalog still fails the whole mint.
Consumers display
this actual inventory rather than inferring delegation from the shared store.

The released legacy `--app-tool app:verb` flag remains supported for existing
callers. When explicitly supplied it selects only those finite tools for that
mint, with no catalog union and no persistent approval. Invalid, missing or
empty explicit selections fail; neither selection path falls back to the other.

Approval is per resident, while requests use that resident's own selected team
certificate. On a host serving multiple customers, each resident approves only
its own apps. As with existing custody snapshots, hostile processes running as
the same OS user are outside this isolation model.

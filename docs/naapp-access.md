# CLI naapp access

A naapp is a declarative HTTP app described by a v1 app manifest. Install it
once for the acting resident identity. From a resident workspace:

```sh
aw plugin install https://notes.example/.well-known/aweb-app.json
aw notes list
```

Local and global residents use their own selected team's certificate for signed
app requests. An attached resident may use `--identity-home` or
`AWEB_IDENTITY_HOME`; commands never fall back to the instance directory.
Installing from that resident home also approves the app for future grants.
Installing an already installed app records approval for this resident too.

For an attached/grant deployment, the resident owner runs one install command:

```sh
aw --identity-home /absolute/resident-root/.aw plugin install https://folio.aweb.ai/.well-known/aweb-app.json
```

`--identity-home` names the **credential directory itself**, containing
`signing.key` and `identity.yaml` or `teams.yaml`. In a workspace layout that is
`<resident-root>/.aw`, not `<resident-root>`. It must belong to the same resident
the session represents. The CLI never guesses a stronger credential or copies a
resident key into a grant home. Grant seats ask their resident owner to perform
this approval; their session credential cannot approve apps.

A new grant minted after this install includes the approved tools. **An already
running grant session keeps its original snapshot**. Install output includes
`identity_home`, `existing_grants_unchanged` and `grant_refresh_command` in JSON,
and prints the replacement action in text. After a resident install or update,
aw also checks that resident's grants in the selected team. When active grants
exist, the receipt reports their count and warns that existing grants do not gain
tools from this install or update. An update does not mean an already delegated
app is absent: its original snapshot still applies. Revoked and expired grants
are excluded. This advisory check has a two-second request budget; if the server
cannot be reached, installation still succeeds and the count is reported as
unknown (`grant_check_error: "unavailable"`), with the same recovery guidance.
JSON reports a known count as `active_grants` (including zero).

The mint action is:

```sh
aw --identity-home /absolute/resident-root/.aw id grant mint --bundle normal-agent --ttl '<ttl>' --custody-socket auto --out /absolute/new-grant-home
```

The resident owner selects the intended scopes (the example uses the
normal-agent bundle) and replaces `<ttl>` with an explicit lifetime, for example
`1h`. Choose `never` only deliberately: it makes the grant revocation-only,
not time-limited. A replacement does not infer the previous session's limits.
`--custody-socket auto` records the selected resident's default custody locator;
the resident's custody service must be running for signed app tools. Omitting
this option produces a grant with no custody locator. The owner supplies a new
empty output directory and restarts the session using that replacement grant.
Do not overwrite the live grant home or change resident identities. Stop the
old session, then relaunch its agent command with the new grant; replace
the entire quoted `'<agent-command>'` token, **including its surrounding
quotes**, with that session's original command line and arguments. Retain the
original quoting of each argument:

```sh
env AWEB_IDENTITY_HOME=/absolute/new-grant-home '<agent-command>'
```

JSON exposes this template as `grant_restart_command`. The CLI cannot discover
which process uses a grant, so it leaves the agent command explicit. A JSON
consumer replaces the placeholder element with the executable and each argument
as separate array elements; it must not place a whole command line in one
executable element.

For an OATS deployment configured with `renew: launch`, use this **alternative**
from the host instead of manually minting and assigning a new grant:

```sh
oats session restart --home /absolute/instance-home
```

The launch renewal mints a fresh snapshot for the same resident. JSON exposes
this conditional template as `oats_renew_restart_command`; replace the instance
home explicitly, since the resident may have several sessions. A readiness pass
or `aw folio help` only proves discovery, not that a live grant has these tools.

App verbs accept the global boolean `--json` before or after the verb, including
`--json=true` and `--json=false`. They return the app's response body unchanged;
the flag is never sent as an app parameter.

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
refused with `app_tool_denied` before an app HTTP request. The CLI explains the
missing delegation and the approve/re-mint/restart remedy; it never updates an
existing snapshot. A deliberately narrowed tool selection remains refused too.

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

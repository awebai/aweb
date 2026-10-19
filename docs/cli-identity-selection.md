# CLI identity selection

Every command selects its acting principal by the same precedence:

1. `--identity-home`, when supplied;
2. otherwise `AWEB_IDENTITY_HOME`, when set;
3. otherwise the current directory's `.aw`, using the existing worktree behavior.

The selected folder supplies the principal's own authority. A selected folder
that is missing, unreadable, corrupt or incomplete returns an error naming that
folder. Unix also checks the owner UID and read/search mode; Windows relies on
profile ACLs and the directory readability check. Credentials, keys and memberships never fall back
to another identity in the checkout. Selecting a principal does not grant server
permissions, expand a session grant or provide namespace/controller authority.

`awconfig.ResolveIdentityHome` implements precedence and directory validation.
`identityHomeForDir`, `resolveClientSelection` and `resolveIdentity` carry that
selection into commands. The command permission allowlist and its default-deny
admission are removed. Identity-independent user-account and utility operations
retain their existing initialization bypass; that bypass supplies no principal.

## State classification

| State | Location and rule |
| --- | --- |
| `signing.key`, `identity.yaml`, own DID/key continuity | Selected identity folder only |
| `context`, `teams.yaml`, `team-certs/` | Selected identity folder only |
| `encryption.yaml`, `encryption-keys/`, archived keys/assertions | Selected identity folder only |
| `grant.yaml`, `grant-signing.key`, custody locator | Selected identity folder only; no root-key/controller fallback |
| `workspace.yaml` service, certificate/member paths and credential workspace ID | Selected identity folder when constructing the acting client |
| Principal inbox indexes and hosted-removal recovery receipts | Selected identity folder; no custom-root reconstruction through checkout `.aw` |
| A2A static caller credentials | Selected identity folder's `a2a-credentials.yaml` |
| `known_agents.yaml`, including configured peer-pin paths | **User trust store, unchanged**; default `~/.config/aw/known_agents.yaml`; no move, copy or migration |
| `~/.awid` namespace/team controller keys and invite records | Existing user-level controller authority, unchanged; not the acting principal's key; a grant cannot borrow it |
| Repository origin/ID, checkout path, presence/repo runtime fields | Checkout/workspace data; no format migration |
| A2A per-task tokens, interaction logs, harness docs/hooks, tmux/worktrees, profile files | Existing checkout/runtime or explicitly named destination |
| User configuration, workspace discovery index, plugins and wake broker state | Existing user/host storage; discovery and placement do not select credentials |

No automatic peer-pin file inside the identity folder is introduced. The common
client and the pin-store commands continue using the existing user trust-store
path. A caller can still explicitly name a pin-store path.

Identity creation must not modify an inherited principal. `id create` and local
invite acceptance require a fresh explicit `--identity-home` target when another
identity is inherited. Their existing clean-target/overwrite checks still run.
`init` only supports an external explicit target for `--workspace-team`;
account/bootstrap and first-agent creation refuse an inherited identity. `aw run`
never starts implicit onboarding when a selected external principal lacks a
workspace connection.
`team admin add` and `workspace add-worktree` keep their explicit target homes
separate from the selected actor. Joining a team with an existing global
identity uses that identity's key; it does not mint another identity.

## Command and direct-path audit

| Group or path | Acting authority and remaining direct paths |
| --- | --- |
| Mail, chat, attachments, events, activity/status, heartbeat | Shared client/identity selection; signing and decryption use selected key material. Heartbeat repo repair reads/writes checkout repo metadata. |
| Tasks, work, locks, instructions, roles | Shared client, including grant clients; server authorization decides each operation. Work/role defaults read the selected credential binding. |
| Contacts, inbound-mode, registry reads, ID request/sign | Shared selection; optional signing-key lookup cannot fall back to checkout when an external actor is selected. Explicit controller/anonymous registry modes keep their documented authority. |
| Team invite | Selected team/service and caller credential; local controller issuance uses that selected team. Grants reach the hosted server under the grant credential and preserve its refusal. |
| Team accept/add/switch/remove/list/members/fetch-cert | Selected identity/membership helpers; certificate installation and rollback use the same root. Explicit fresh-target acceptance is separate from inherited actor state. |
| Team create/admin provisioning, extend, reissue/replace-key | Actor resolution uses the selected folder; child identities and operator repairs keep their explicitly named target paths. External actors do not discover another local agent's credential as a fallback. First-agent creation refuses an inherited identity. |
| Workspace status/connect/delete/add-worktree/migrate | Selected credential binding; existing lifecycle refusals remain. Checkout placement and named new worktrees stay explicit. Migration targets the selected credential files, with no new migration or file format. |
| Doctor/check/support bundles and fixes | Existing `*At` helpers receive the selected folder; diagnostic checks and fixes do not inspect a decoy identity. |
| Run/custody/app approvals, MCP config | Shared selection; subprocesses retain the selected home. Explicit outputs/runtime destinations remain separate. |
| Beads/GC mail adapters | Shared messaging resolver and selected-principal inbox index; address maps remain adapter/workspace data. |
| Wake, plugins, local harness/profile setup | User/host/runtime storage and explicitly named registrations/targets. Plugin helper subprocesses inherit the selected identity folder; no checkout key substitutes for actor authority. |
| Reset/local cleanup | Existing explicit cleanup boundaries protect the inherited principal; no implicit principal deletion through a checkout operation. |

Remaining `Worktree*`/`LoadTeamState(dir)` calls are confined to default-selection
branches or named creation/repair destinations: onboarding/connect helpers,
`id create` planning, team-member enrollment, reissue/replace-key, and checkout
runtime/profile operations. These path APIs deliberately do not consult the
process environment: doing so would redirect an explicitly named child target
into the caller's inherited identity.

## Evidence boundaries

Production-binary tests use different checkout, environment and flag keys. They
verify the actual request signatures for mail, chat, team invite, contacts,
inbound-mode, tasks, ID requests and workspace status, with flag precedence and
unchanged default selection. Hosted invites, controller invite/global acceptance,
explicit fresh hosted-local acceptance, grant refusal, missing/empty selection,
wrong-owner/readability checks and inherited-init protection cover the neighboring
operations. The HTTP fixtures are local contract fixtures, not deployed-stack
acceptance. Native Windows CI also exercises the precedence and invite binaries.

# This repository in an OATS workspace

The aweb maintainers run their agents on [OATS](https://github.com/awebai/oats)
workspace model v2. This repository is a **member** of an OATS workspace that is
hosted in another repository. `oats-membership.yaml` at the root names that
host and completes the membership handshake. The workspace declaration
(members, pinned packages, teams, defaults and knowledge stores) and the
deployment runbooks live with the host, not here.

What this repository contributes to the workspace lives here:

| Path | What it is |
|---|---|
| `souls/<name>/` | The souls: `soul.yaml`, `AGENTS.md` (`CLAUDE.md` links to it) and `okf.json`, the knowledge nodes the soul owns and reads. |
| `souls/coordinator/` | The team's cross-repository coordinator. |
| `souls/aweb-expert/` | OSS direction, architecture, adoption and integration judgment. |
| `souls/aweb-protocol-expert/` | The open protocol contracts: identity, teams, federation, messaging, events, the `aw` CLI and runtime integrations. |
| `knowledge/` | The aweb knowledge base (id `aweb-oss-knowledge`): one node per soul, owned by the id in `knowledge/okf-base.json`. Each soul's `okf.json` refers to it under the base alias `aweb` (`aweb/<node>`). |

A soul directory must not contain a `knowledge/` bundle: OATS refuses to spawn
such a soul, so `souls/*/knowledge/` is gitignored. The `agents/` tree holds
the souls' earlier records, which OATS v2 does not discover.

## Public contributors

If you can read this repository but not the workspace host, OATS gives you the
standalone view (see
[The standalone case](https://github.com/awebai/oats/blob/main/docs/workspaces.md#the-standalone-case)
in the OATS documentation). These souls are still listed and spawnable, with
the framework's own operational package. The workspace's defaults and pinned
packages are not visible there, so a standalone instance runs without the
knowledge and messaging layers the maintainers' workspace provides. Name this
repository in your `oats-local.yaml` (`workspace:` or `standalone:`) and the
kernel falls back to that view.

Changes to a soul or to the knowledge base are ordinary pull requests to this
repository, reviewed like any other change.

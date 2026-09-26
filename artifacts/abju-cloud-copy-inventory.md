# abju Cloud copy / operator surface inventory

This OSS change keeps the interoperable client contract in this repository and does not require a Cloud schema migration or a new server endpoint. It does change CLI examples and onboarding copy wherever Cloud/operator surfaces tell a user to run clean-root `aw init`.

## Required Cloud copy sites

Concrete Cloud repository paths identified for operator review/update:

- `site/static/docs/cli-tutorial.md`
  - Hosted fresh-account examples must include the explicit outcome, e.g. `aw init --new-account --username <u> --name <name>` (plus `--global` when creating a hosted global identity).
  - Self-hosted/local examples must include `--new-team` for clean-root team creation.
  - Existing reconnect examples where a certificate is already installed may remain plain `aw init` because they bind an existing certificate rather than create an outcome.
- `site/layouts/_default/teams.html`
  - Hosted hero / “automatic account” copy must stop implying that plain clean-root `aw init` silently creates an account/team. It should describe explicit hosted account creation with `--new-account`.
- `site/layouts/index.html`
  - Self-hosted examples must use `aw init --new-team ...` for first local team creation.
  - Any chooser explanation should say the machine index is discovery-only and that TTY choices complete the selected outcome in-process; no-TTY/JSON prints rerun guidance.
- `DeveloperToolsInstructions.tsx`
  - Any clean-root setup snippet should choose an explicit outcome (`--new-account`, `--new-team`, `--join-from`, `--admission-team-id`, or `--personal-workspace`).
  - Preserve API-key onboarding examples: API-key bootstrap is already an explicit authorization path and continues to be supported.

Historical screenshots/demo captions can stay historical if they are clearly not current instructions.

## OSS behavior/copy updated here

- `--admission-team-id <team>` uses existing `cli.team_admission` device-login scope and existing admission-invite endpoint (`/api/v1/teams/{team_id}/admission-invite`). Missing auth starts bounded device flow in TTY and non-TTY/JSON; TTY refusal exits nonzero and prints `aw auth login --scope cli.team_admission`.
- `--personal-workspace --workspace-key <key> --identity-home <root>` uses existing personal workspace ensure/enroll endpoints. The identity-home root is explicit and preserved as explicit provenance; it is never inferred from cwd.
- `--join-from <path> [--join-team <team>]` is local client orchestration: it mints one invite from an existing local workspace or identity home and then accepts/connects in the current worktree.
- The machine workspace index is local-only discovery at `~/.config/aw/workspaces.yaml`. It is nonsecret, not uploaded, and not authority. Unavailable roots remain listed with availability details.
- Global joins through `aw init --join-from` / `--admission-team-id` reuse existing global accept-invite semantics: an existing self-custodial global identity is required. The CLI fails with `aw id create` guidance rather than silently using local scope.

Public OSS docs updated in this branch:

- `cli/go/README.md`: quick CLI examples for explicit init outcomes and distinction between fresh hosted global creation and global join reuse.
- `docs/aweb-sot.md`: lifecycle source-of-truth for explicit init outcomes, workspace discovery index, admission device auth, personal workspace identity-home boundary, and global join semantics.
- `docs/identity.md`: identity-scope rule for init join/admission paths and personal-workspace identity-home boundary.
- `docs/self-hosting-guide.md`: first local workspace example now uses `--new-team`; reconnect examples are unchanged.
- `docs/cli-command-reference.md`: regenerated command reference including new init flags/help.
- `scripts/e2e-oss-user-journey.sh`: local quickstart gate now checks missing-outcome refusal and uses `--new-team` for clean-root creation/retry.

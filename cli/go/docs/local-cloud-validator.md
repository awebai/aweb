# Local Cloud Validator

`scripts/validate_local_cloud.py` boots `../aweb-cloud` via its existing
`make local-container` path, builds the current `aw` CLI, and runs real CLI
flows through a local recording proxy.

The validator is designed for endpoint-contract checking, not mock testing:

- it creates isolated personas with separate `HOME` / `XDG_CONFIG_HOME`
- it creates temporary git repos and plain directories as workspaces for those personas
- it records every HTTP request that `aw` sends during each command
- it writes a JSON report with command output, observed requests, and endpoint coverage

## Run

```bash
make local-cloud-validate
```

or:

```bash
python3 scripts/validate_local_cloud.py
```

## Current Coverage

The current suite exercises real multi-user flows with dedicated personas:

- `owner`: creates the project and drives most project-scoped commands
- `implementer`: joins via spawn and receives mail/chat
- `reviewer`: exercises the permanent identity path when that path is working
- `connector`: imports an existing identity with `aw connect`

The suite currently drives:

- `aw project create`
- `aw init` into an existing project
- `aw init` for a non-git local directory attachment
- `aw project`
- `aw project namespace list|add|delete`
- `aw policy show`
- `aw policy roles`
- `aw whoami`
- `aw identities`
- `aw identity log`
- `aw identity access-mode` get/set
- `aw identity reachability` get/set
- `aw identity rotate-key`
- `aw identity delete`
- `aw workspace status`
- `aw spawn create-invite`
- `aw spawn list-invites`
- `aw spawn accept-invite`
- `aw spawn revoke-invite`
- `aw mail send|inbox|ack`
- `aw chat send-and-wait|pending|open|history|extend-wait`
- `aw contacts add|list|remove`
- `aw directory` search/get
- `aw lock acquire|list|renew|release|revoke`
- `aw task create|list|show|update|comment|dep|close|reopen|delete|stats`
- `aw work ready|active|blocked`
- `aw events stream`
- `aw connect`

The validator keeps going past non-critical command failures so the report can
surface a broader set of contract mismatches from one run.

## Output

By default the script writes:

- JSON report: `artifacts/local-cloud-validation-report.json`

The report includes:

- command argv / cwd / stdout / stderr / exit code
- persona name for each command
- all observed requests per command
- per-command validation errors
- expected endpoint prefixes per command
- missing expected endpoint prefixes, if any
- endpoint inventory coverage showing which user-facing API routes were exercised
  and which still need fixtures or more scenarios

## Notes

- The validator assumes `../aweb-cloud` exists and Docker is available.
- It uses temporary ports unless you override them.
- Use `--keep-temp` if you want to inspect the generated temp repos/config.
- Use `--leave-stack-running` if you want to keep the local container stack up
  after the validator exits.
- Some routes still require dedicated fixtures and are intentionally not treated
  as locally automated yet, such as DNS namespace verification and human-claim
  flows.

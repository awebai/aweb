# Password CLI fixture

`cli.py` is the standalone native exec client for the S19/M9 release job. It
uses Python's standard library and authenticates to the existing test
upstream's `GET /basic/echo` over verified TLS. It consumes the password only
from `AWEB_SECRETS_E2E_CLI_PASSWORD` and prints exactly `authenticated` on
success (exit 0), or `refused` on failure (exit 1). Stderr is empty. It never
prints the response body, request headers, arguments or exceptions, and does
not follow redirects or use ambient proxy settings. Requests have a fixed
10-second socket timeout; the runner's job deadline still applies.

Invoke it as a pinned job, using absolute paths:

```text
/absolute/python -I /absolute/cli.py --origin https://test-upstream.example \
  --username <non-secret-fixture-username> --ca-file /absolute/test-ca.pem
```

The origin must be HTTPS, with no user information, query, fragment or path
other than `/`. The client always requests `/basic/echo`. The CA file is
explicit; missing configuration or an untrusted certificate refuses.

S19 owns receiver startup and fixture synchronization. It gives the receiver
its independently held copy of the same fresh password stored in the vault's
CLI field, and supplies the non-secret username above. The client does not
read the vault, hold its writer token or start another service.

For the approved `job/1` and matching local `RunnerConfig`:

- Set `kind` to `exec`, pin the absolute Python executable in `exec.path` and
  `exec.sha256`, and declare the script and CA file in `exec.files` with their
  exact SHA-256 hashes (sorted by path).
- Put `-I`, the script path and the public options in the job's literal args.
- Bind `AWEB_SECRETS_E2E_CLI_PASSWORD` to the approved credential slot/field
  matching that secret's kind. The environment name does not select a codec
  or imply that every kind calls its field `password`.
- Provision the runner-owned protected configuration, working directory and
  installed files using M7's existing ownership rules. The fixed job digest
  and allowed runner IDs must match both the confirmed server record and the
  local pin.

The focused tests exercise the actual child CLI and TLS receiver with generated
fixture values. They do not establish the vault synchronization, provisioned
runner UID, S13 dispatch/approval path or complete release journey.

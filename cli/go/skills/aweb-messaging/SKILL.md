---
name: aweb
description: Agent-to-agent messaging with the aw CLI. Use team-local aliases or persistent addresses, and rely on team-certificate workspace auth.
homepage: https://github.com/awebai/aweb/tree/main/cli/go/skills/aweb-messaging
metadata: {"aweb":{"emoji":"💬","requires":{"bins":["aw"]}}}
---

# aweb Messaging

Use this skill when the workspace is already connected to a team or when you
need to diagnose whether messaging is ready to use.

Authoritative references:

- `docs/agent-guide.txt`
- `docs/aweb-sot.md`
- `docs/awid-sot.md`

## Check Readiness

```bash
aw whoami
```

If that succeeds, the workspace is connected.

If it fails:

- Check whether `.aw/workspace.yaml` and `.aw/team-certs/` exist
- If the workspace is uninitialized, ask the user to run `aw run <provider>`
  or the explicit invite flow:

```bash
aw id team accept-invite <token>
AWEB_URL=<server-url> aw init
```

Do not instruct users to use legacy project bootstrap commands.

## Start-of-Session Checklist

```bash
aw mail inbox
aw chat pending
aw work ready
```

Respond to anything urgent before starting other work.

## Mail

```bash
aw mail send --to <alias-or-address> --subject "<subject>" --body "<body>"
aw mail inbox
```

- `--to` accepts a team alias such as `bob` or a persistent address such as
  `acme.com/bob`
- Use mail for non-blocking coordination

## Chat

```bash
aw chat send-and-wait <alias-or-address> "<message>" --start-conversation
aw chat send-and-wait <alias-or-address> "<message>"
aw chat send-and-leave <alias-or-address> "<message>"
aw chat pending
aw chat open <alias-or-address>
aw chat history <alias-or-address>
aw chat extend-wait <alias-or-address> "working on it, 2 minutes"
```

- Chat is the synchronous path; use it only when a reply is needed to proceed
- Both participants must be online for real-time exchanges

## Contacts

```bash
aw contacts list
aw contacts add acme.com/alice --label "Alice"
aw contacts remove <address>
```

## Tips

- Persistent addresses use the canonical `namespace/name` form
- Mail is durable; the recipient can read it later
- Chat is real time; both sides must be online
- Team membership and coordination auth come from the active team certificate referenced from `.aw/workspace.yaml`

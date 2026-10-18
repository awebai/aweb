# Hermes Aweb platform plugin

Prototype Hermes gateway platform for Aweb agent mail/chat.

This is a real Hermes platform adapter, not a docs-only `aw init` recipe. It registers `ctx.register_platform(name="aweb", ...)`, starts `aw events stream --json`, fetches actionable message bodies through the `aw` CLI, injects them into Hermes as `MessageEvent`s, replies with `aw mail reply` / exact `aw chat send --session-id`, and only then marks the triggering message read with `aw mail ack` / `aw chat read`.

## Current install shape

For local testing, copy or symlink this directory into Hermes' user plugin directory:

```bash
mkdir -p ~/.hermes/plugins/platforms
ln -s /path/to/aweb/packages/hermes-aweb-platform ~/.hermes/plugins/platforms/aweb
hermes plugins enable platforms/aweb
```

Then configure an Aweb workspace for the Hermes gateway identity:

```bash
cd /path/to/hermes-aweb-workspace
aw workspace status
```

Set env in `~/.hermes/.env` or via `hermes gateway setup`:

```bash
AWEB_PLATFORM_ENABLED=true
AWEB_PLATFORM_WORKDIR=/path/to/hermes-aweb-workspace
AWEB_PLATFORM_AW_BIN=aw
AWEB_ALLOW_ALL_USERS=true        # dev only; prefer AWEB_ALLOWED_USERS in real use
# AWEB_ALLOWED_USERS=example.aweb.ai/alice,example.aweb.ai/bob
# AWEB_HOME_CHANNEL=example.aweb.ai/alice
```

Use a native workspace in `AWEB_PLATFORM_WORKDIR`, with `AWEB_IDENTITY_HOME`
unset in the gateway environment. aw 1.36.40 refuses `events stream` with an
external identity home. Allowlist the sender address shown by aweb when present;
the adapter prefers that address over the team alias.

Start Hermes gateway:

```bash
hermes gateway restart
hermes gateway status
```

## Requires aw CLI support

The adapter needs machine-safe read acknowledgement commands:

- `aw mail ack <message-id> --json`
- `aw chat send --session-id <session-id> --body-file <path> --leave --json`
- `aw chat read --session-id <session-id> --message-id <message-id> --json`

Those are added in this same change because existing `aw mail inbox` / `aw chat open` acknowledge by side effect and are not precise enough for a gateway adapter.

## MVP scope

- Inbound Aweb actionable mail and chat.
- Outbound plaintext replies through current aw defaults (`--plaintext` is explicit in the adapter).
- No media attachments.
- No Hermes-side Aweb identity creation; create/bootstrap the aw workspace first.
- No server-side Aweb changes.

## Main blocker resolved here

Before this adapter, Aweb had an event stream and body fetch commands, but no stable CLI command to reply to an exact chat session or ack/read a specific message after Hermes confirmed delivery. The new `aw chat send --session-id`, `aw mail ack`, and `aw chat read` commands close that adapter contract gap.

## Compatibility checks

The lifecycle regression imports a real Hermes checkout and calls its actual
gateway lifecycle methods. Use that checkout's dependency environment:

```bash
HERMES_AGENT_SOURCE=/path/to/hermes-agent \
  python -m unittest discover -s packages/hermes-aweb-platform/tests \
  -p test_hermes_lifecycle.py -v
```

The opt-in live regression additionally needs isolated local e2e identities and
the stack's PostgreSQL container. Stop any other gateway consuming the receiver.
It starts a real gateway and uses `/help` and `/start`; no model key is needed.

```bash
HERMES_AGENT_SOURCE=/path/to/hermes-agent \
HERMES_LIVE_RECEIVER_HOME=/path/to/local-hermes-workspace \
HERMES_LIVE_SENDER_HOME=/path/to/local-alice-workspace \
HERMES_LIVE_POSTGRES_CONTAINER=hermes-acft1-postgres-1 \
  python -m unittest discover -s packages/hermes-aweb-platform/tests \
  -p test_live_chat.py -v
```

The sender fixture's team alias is `alice`, the receiver's is `hermes`. The test
requires a receiver bound to a loopback aweb URL and uses the disposable e2e
database to hold one read receipt while restarting the real stream process.
These checks establish transport behavior, not model-generated replies.

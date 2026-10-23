# CLI

This directory groups client implementations for `aweb`.

Current implementation:

- `go/` — the Go CLI and protocol client, shipped as the `aw` command

This layout leaves room for future client implementations without forcing a
repo-wide reshape later.

Global recipients can use `aw inbound-mode contacts-only` to accept mail and chat
only from exact active identity contacts. Verified teammates also need a contact.
The canonical API value is `contacts_only`; `team_and_contacts` retains its
teammate allowance. See [the Go CLI guide](go/README.md#inbound-modes).

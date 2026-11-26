---
type: Lesson
title: An unread Settings field can be startup validation
description: A server Settings field that nothing reads is not dead when get_settings() builds it at startup and its getter validates the env var; removing it moves a configuration error from boot to the first request that reads the variable. Report "unread" and "dead" as different findings.
tags: [lesson, cleanup, configuration, server, review]
timestamp: 2026-11-26
---

In the 2026-11-24 aweb dead-code sweep, vulture reported several fields of the
server's `Settings` dataclass (`server/src/aweb/config.py`) as unread. It was
right: on main df2f356b4, nothing outside `config.py` reads
`presence_ttl_seconds`, `require_registered_certificates`,
`app_grant_max_age_seconds`, `hook_producer_keys`, `federation_outbound` or
`app_internal_origins`. But the fields are not dead:

- each env var is read at call time by its own getter, where it is used;
- the application lifespan in `api.py` calls `get_settings()`, which builds
  every field through that getter, so an invalid value refuses startup.

Removing such a field keeps the feature working but moves the configuration
error from boot to the first request that reads the variable. For a
fail-closed setting like the outbound federation switch, that means a server
that starts and then refuses every delivery. `get_federation_outbound` says so
in its own docstring. The other fields carry no such note, so a dead-code
pass flags them again on every run.

The source kept the fields. The coordinator had proposed removing them, and
the source sent its reasons for keeping them back (coordinator mail e7fbd03c
and the reply, 2026-11-24/25). The coordinator's final ruling is not in the
evidence. Removing these fields reopens that question; it is not a cleanup.

# How to apply

- Before removing a config field that nothing reads, check two things: whether
  its env var is read elsewhere at call time, and whether building the field
  at startup is the only boot-time check of that variable.
- If it is, keep the field, or move the validation into an explicit startup
  check in the same change.
- Report "unread" and "dead" as separate findings in a dead-code inventory.

The elimination route is in the code: a comment on `Settings` saying that
building the fields validates the env vars at startup, or a test that an
invalid value refuses startup. Either stops the field being flagged as dead
again.

This refines
[verify business facts; consolidate before cutting](/aweb-expert/lessons/verify-business-facts-and-consolidate-before-cutting.md)
for configuration flagged as dead by a tool.

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-26;
notes/unread-settings-fields-validate-at-startup.md. The unread fields and
the startup `get_settings()` call were checked by the harvester on main
df2f356b4. The decision thread is source-reported.

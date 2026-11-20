---
type: Lesson
title: Docker Desktop binds prove mode and a read, not ownership or isolation
description: On a Docker Desktop host bind, a container's chown exits 0 without storing the owner and any container uid can read a 0400 file, so a test that must pass on a Mac gate asserts a regular file, its mode and an actual read by the consumer uid, reports the owner as a diagnostic, and leaves ownership and isolation of credentials to a Linux daemon.
tags: [lesson, docker, e2e, testing, permissions, secrets]
timestamp: 2026-11-14
---

A credential-staging test naturally asserts "owned by the service uid and
readable by no one else". On a Docker Desktop host bind (macOS file sharing)
that assertion cannot pass. Worse, the step that should establish it looks
successful:

- `chown` from a root container exits 0 but the owner is not stored. The
  container then sees the file as `0:0`, and the host sees it as the host
  user's.
- `chmod` is stored: the container sees mode 0400.
- Container uid boundaries are not enforced on the bind. Containers running as
  two different non-root uids could both read the 0400 files.

So on Desktop a chown that "succeeds" proves nothing, and a passing Mac run is
no evidence that production credential files are isolated.

# How to apply

- A test that must pass on a Mac Desktop gate asserts only what Desktop keeps:
  each staged file is a regular file in the daemon's view, it has the intended
  mode, and a container running as the consumer uid actually reads it.
- Report the owner as a diagnostic, labelled as not asserted, and make no
  claim that other uids cannot read the file.
- Prove ownership and isolation of credentials on a Linux daemon, such as the
  customer VM, where chown and permission semantics apply. Never infer them
  from a Mac run.
- An exit status is not the property. Check what the step was meant to
  establish, in the view of the process that will rely on it, as
  [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
  says of exit-code checks.

The OSS user journey's customer-secrets phase takes this shape: mode 0400 plus
a uid-1001 read, with the owner reported (a8156b593, aweb-acwd.24.12). Its
comment records the reason. Other staging tests do not inherit that comment,
so this lesson is the route for new ones.
[Docker published ports are not a stable test path](/aweb-protocol-expert/lessons/docker-published-ports-in-tests.md)
is a separate Docker Desktop trap, about networking.

# Limits

The Desktop behaviour was observed once, on one Desktop version and one host,
on 2026-11-14 (source-reported). The Linux behaviour is the standard chown and
permission semantics and was not re-observed in that proof.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-14;
notes/desktop-binds-do-not-store-ownership.md.

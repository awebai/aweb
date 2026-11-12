---
type: Lesson
title: A gate asserts the property, not a proxy for it
description: A gate test asserts the property it protects, not one platform's CLI behaviour, and a fix satisfies a contract test's stated property, not its pattern; Docker Desktop accepts a duplicate loopback publish with exit 0 where native Linux refuses, and a path derived from the package's own location passed a no-sibling-path regex while keeping the forbidden assumption.
tags: [lesson, testing, gates, review, docker, portability]
timestamp: 2026-11-12
---

Two failures on the move of the gates to Linux VMs (2026-11-11..12) had the
same shape: what was checked stood in for what mattered.

- **A platform's CLI behaviour stood in for a property.** Docker Desktop
  accepts `docker run -p 127.0.0.1:<taken>:80` with exit 0, starts the
  container and publishes nothing. Native Linux refuses the same command. A
  test that asserts the refusal passes on one platform and fails on the other,
  and says nothing about the port either way. The property is port ownership:
  the competitor holds no binding, and a request from the host to the port
  still gets the original service's distinguishable response. From inside a
  bridge-network runner 127.0.0.1 is not the Docker host, so that check runs on
  the host. The check on main and its two accepted outcomes are described in
  `docs/release.md` (the candidate publication controls).
- **A test's pattern stood in for its property.** A contract test forbade a
  package from assuming where its host repository lives, and enforced that with
  a regex against sibling paths. A fix derived the repository root from
  `MAKEFILE_LIST` and `../..`: it passed the regex and kept the location
  assumption. The fix that met the property has the caller supply the path,
  and the package refuses when it is unset. It never reconstructs the path from
  its own location.

# How to apply

- When writing or reviewing a gate assertion, name the property in one
  sentence first. Then check that the assertion holds or fails on that
  property alone on every supported host (Docker Desktop and native Linux at
  least), not on how one tool reports it.
- When a contract test goes green after a fix, read the test's stated purpose
  and ask whether the fix meets it, not only whether it avoids the pattern.
  A green regex is evidence only for the pattern.
- A dependency the package needs from its host repository is an explicit
  input from the caller, refused when missing.
- Pin a probe image by its multi-architecture index digest. A
  platform-specific manifest digest runs emulated on the other architecture,
  and the emulation confounds any diagnosis made with it.

The elimination route is in the tests themselves: a contract test that checks
behaviour (run the package from a relocated copy and expect a refusal when the
path is unset) cannot be passed by a pattern. Until contract tests are written
that way, this is a review habit. A green that does not name its property is
the kind of harness that
[must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).
This refines
[Docker published ports are not a stable test path](/aweb-protocol-expert/lessons/docker-published-ports-in-tests.md)
with the Desktop behaviour for a duplicate publish.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-12; notes/gate-lessons-2026-11-12.md. The Desktop behaviour is the
source's report from the diagnostic at e4cebc724. The host-side ownership
check (b7dca1767) and its documentation in `docs/release.md` were read on main
at 71e608a1c. The `MAKEFILE_LIST` case is the source's report; the harvester
did not find it on main.

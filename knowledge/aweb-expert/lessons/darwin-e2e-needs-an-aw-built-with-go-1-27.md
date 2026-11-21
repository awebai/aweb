---
type: Lesson
title: On macOS, naapp e2e needs an aw built with Go 1.27 or later
description: The e2e helpers make aw trust the disposable stack CA through SSL_CERT_FILE plus GODEBUG=x509sslcertoverrideplatform=1, a setting that exists only from Go 1.27; on darwin an aw built with an older Go uses the platform verifier, rejects the test CA, and the failure is harness setup, never product evidence or a valid red.
tags: [lesson, testing, e2e, naapp, tls, macos, go]
timestamp: 2026-11-18
---

The naapp e2e helpers run whichever `aw` is first on `PATH` and point it at the
disposable stack's CA with `SSL_CERT_FILE` and
`GODEBUG=x509sslcertoverrideplatform=1`. That GODEBUG setting was added in Go
1.27 (`internal/godebugs/table.go` records it as `Changed: 27`). On darwin,
an `aw` built with Go 1.26 ignores both settings and verifies with the
platform verifier, which does not know the test CA.

The symptom is every case failing with `x509: certificate is not trusted`
from `aw`, before any request reaches the app under test. On 2026-11-18 a
packaged `aw` built with go1.26 failed every case of a new Library
authorization e2e test this way, and the Library e2e suite failed 17 cases.
With an `aw` built from source with Go 1.27, the same suite passed all 24.

# How to apply

- Check the Go version of the `aw` on `PATH` (`go version -m "$(command -v aw)"`)
  before a naapp e2e run on a Mac.
- Build `aw` from the candidate's own `cli/go` with a Go 1.27 or later
  toolchain and put it first on `PATH` for the run. The run then also exercises
  the candidate CLI instead of a released one. `cli/go/go.mod` may declare an
  older minimum, so the local toolchain decides which version the binary gets.
- A failure in this shape is harness setup. Never report it as the expected
  red of a new test or as a product regression; a red counts only if it names
  the property, as [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
  says.
- The rule is known only for darwin. That Linux gate VMs are unaffected
  (Linux honours `SSL_CERT_FILE` natively) is an unchecked hypothesis.
- The elimination route is a preflight in the e2e helpers: on darwin, refuse
  to start when the `aw` on `PATH` was built with Go older than 1.27, and name
  this cause. Until that exists, this lesson is the guard.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-library-auth, 2026-11-18; notes/darwin-aw-test-ca-trust.md. The GODEBUG version was rechecked in the Go 1.27.4 source at harvest.

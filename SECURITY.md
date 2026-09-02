# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately, either through
[GitHub private vulnerability reporting](https://github.com/awebai/aweb/security/advisories/new)
or by email to hello@aweb.ai with "Security" in the subject. Include the
component (server, AWID registry, `aw` CLI, channel, Pi extension, or the
hosted service at app.aweb.ai), the version, and steps to reproduce.

A maintainer will reply, work with you on a fix, and credit you in the
changelog if you want that. Please give us time to ship the fix before any
public disclosure.

## Scope

The code in this repository and the hosted service at app.aweb.ai. The
security model is documented in the [aweb SOT](docs/aweb-sot.md) and the
[AWID SOT](docs/awid-sot.md); a report that shows those contracts can be
violated is in scope even when no code path is obviously broken.

## Supported versions

The latest published version of each artifact (see [docs/release.md](docs/release.md)
for the artifact list). Fixes ship as new versions; nothing is backported.

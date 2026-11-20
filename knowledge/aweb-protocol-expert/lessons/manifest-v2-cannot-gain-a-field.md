---
type: Lesson
title: App manifest version 2 cannot gain a field
description: Released aw from 1.36.46 to 1.36.56 decode manifest v2 strictly with one unchanged field set, as do aweb_naapp.manifest and the server, so a new app declaration ships as a new manifest version served as a catalog variant beside v2, never as a v2 field.
tags: [lesson, compatibility, app-manifest, released-clients, discovery]
timestamp: 2026-11-07
---

Manifest version 2 is decoded strictly everywhere it is read: the `aw` Go
decoder refuses unknown fields at every level, and so do `aweb_naapp.manifest`
and the server. Every released `aw` from 1.36.46 to 1.36.56 carries the same
v2 field set. A field added to v2 looks additive, but every released client
that installs an app declaring it refuses the manifest. This is
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
applied to a decoder that has no unknown-field tolerance; the operator's
2026-10-20 waiver for the install surfaces predates these releases and does
not cover them.

The release range is not visible on main: it took comparing the `json` tags
of `cli/go/internal/appmanifest/manifest_v2.go` at the `aw-v1.36.46` and
`aw-v1.36.56` tags and on main (verified again at harvest, 2026-11-08: the tag
sets are identical and the strict unknown-field refusal is present at each).

# How to apply

- Never propose "add a field to manifest v2". Start from a new manifest
  version, or from a vehicle outside the manifest.
- A new version is served through the existing variant discovery
  (`docs/app-manifest.md#variant-discovery`): the app's catalog lists v2 and
  the higher version, and each consumer picks the highest version it supports,
  so released clients keep installing v2.
- Price the cost in the design: the server and the hosted gateway must support
  the new version, and existing installations must be re-pinned to it. A
  re-pin is an update: it bumps the installation's generation and supersedes
  its hook bindings.

# Status

This route was adopted as the design for owner-act declarations
(`owner_acts` in a manifest version 3, aweb-acgh.16.38, branch commit
9283451be) and ACKed by the independent reviewer and the security reviewer; the
operator's ruling on that design was pending on 2026-11-07. The discovery
above holds whatever that ruling decides.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-07; notes/manifest-v2-is-frozen-for-released-clients.md.

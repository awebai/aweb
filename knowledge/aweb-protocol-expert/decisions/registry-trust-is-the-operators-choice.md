---
type: Decision
title: Registry trust is the operator's choice in this process
description: The Go client (aw, the A2A gateway) trusts a registry origin with its own HTTP client only when the operator chose it for this process (the built-in default, AWID_REGISTRY_URL, a registry flag on the current command line, or a daemon's own operator-authored config or startup environment); state the program writes or receives never counts, because it can launder a value from DNS or a remote party. Every other origin is pinned to public https. On main and in aw-v1.36.59-rc.2.
tags: [decision, aw-cli, awid, registry, a2a-gateway, security, federation]
timestamp: 2026-11-13
---

**Status (verified 2026-11-20):** decided 2026-11-13 by aweb (directions B1
and option 1, task aweb-aczi; refined after RC2 gate #10, task aweb-adae),
each with a security-fixes ACK. Both are on main (babe5add8, 0bd6bd986) and
first in aw-v1.36.59-rc.2. The operator-facing list of trusted and pinned
origins is in `docs/self-hosting-guide.md`, "Private Registries and the aw
CLI"; this concept records why the line sits where it does.

# Decision

- **The line is authorship.** A registry origin counts as the operator's
  choice only if the operator wrote it for this program: the built-in
  default, `AWID_REGISTRY_URL`, a registry flag on the current command line,
  or, for a daemon such as the A2A gateway, the registry in its own
  operator-authored config file or startup environment.
- **State the program writes or receives never counts:** `identity.yaml`,
  `teams.yaml`, controller metadata, invites, service discovery, `_awid` TXT
  and other DNS answers, or a managed config fetched over the network. Those
  origins are pinned to public `https`, without proxies, with every DNS
  answer checked before dialling.
- **The only exception is isolated development** (`APP_ENV=development` and
  `AWEB_FEDERATION_TEST` enabled, isolated hosts only), mirroring the
  federation origin contract in `docs/aweb-sot.md`.
- **One fix for a private self-hosted registry:** `AWID_REGISTRY_URL` in the
  process environment for `aw`; the gateway's own `registry_url` for the
  gateway. `aw doctor` and the refusal text both name it.

# Why

A stored value is not evidence of intent. `identity.yaml` and `teams.yaml`
are written by the program from what an invite, discovery or DNS answer
supplied, so "it is in local config" can mean "a remote party put it there".
Only what the operator authored for this process (its environment, its
argv, a daemon's own config) shows that a human chose to reach that origin.

# Rejected and refined

- **Trusting stored config** (`registry_url` in `identity.yaml` or
  `teams.yaml`) as operator intent: rejected for the laundering reason above.
- **First cut, refined:** B1 initially pinned the gateway's configured
  `registry_url` too. After gate #10 the decision was refined: a daemon's own
  operator-authored config is the daemon's equivalent of argv. A gateway
  whose registry appears only in `teams.yaml` stays pinned (mutation-tested
  in the security review). This refinement was a contract change ruled by
  the owner, not a fix made inside a failing gate; see
  [accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md).

# Consequences for future work

- A new registry call site goes through the resolver's or client's
  `httpClientFor` (`cli/go/awid/registry_pin.go`), and a new registry flag is
  added to the trusted command-line origins (`cli/go/cmd/aw/registry_trust.go`);
  never a raw HTTP client.
- A test with a loopback fake registry names it through `AWID_REGISTRY_URL`
  or a flag. A test of **which** registry gets selected uses isolated
  development instead, because naming the registry would bypass the branch
  under test.
- Deploy advice for a private registry is always `AWID_REGISTRY_URL` (or the
  gateway's own `registry_url`), never editing stored identity or team files.

Related: [unauthenticated input must not drive remote work](/aweb-protocol-expert/lessons/unauthenticated-input-must-not-drive-remote-work.md),
[sweep every package, harness and process after a shared change](/aweb-protocol-expert/lessons/sweep-every-consumer-of-a-shared-change.md).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-local-log-encryption, 2026-11-13; notes/registry-trust-is-operator-choice.md. Verified by the harvester on 2026-11-20: babe5add8 and 0bd6bd986 are ancestors of aweb main and first tagged in aw-v1.36.59-rc.2; the trusted and pinned origin lists match `docs/self-hosting-guide.md` on main. The decisions themselves and the security ACKs are source-reported.

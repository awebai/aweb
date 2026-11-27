---
type: Lesson
title: Only the explicit exchange starts an ID chain
description: aw's automatic provisioning paths only pass on a chain the creator already has, so a chainless creator silently yields membership-only children reported as legacy_no_chain; the first chain comes only from the explicit root-signed or person-signed parent exchange, and the reserved `local` namespace cannot start one.
tags: [lesson, identity, id-chain, provisioning, oats]
timestamp: 2026-11-27
---

Discovered while classifying why every OATS seat of a team showed
`legacy_no_chain`. The cause was the minting root, not the seats.

# What propagates and what does not

- **Automatic provisioning only carries an existing chain.** `aw init`, native
  and hosted invites, `--join-from` (the OATS spawn), `--parent`, team admin and
  add-worktree all have the creator sign the child only when the creator already
  has a chain or a stable ID. A chainless local creator falls through silently
  and produces a membership-only child, which verification reports as
  `legacy_no_chain` and the released disposition lets continue.
- **The first chain comes only from the explicit exchange.** The issuer is
  either the namespace root (`aw id child invite --as-root`, giving `no_human`)
  or a person. The steps: the issuer's `id child invite`, the child's
  `id parent request`, the issuer's `id child receive` and `id child approve`,
  and the child's `id parent import`. A local child needs no registry write,
  but verifying its chain needs root evidence.
- **Bare `aw init --new-team` cannot start a verifiable chain.** It uses the
  reserved localhost namespace `local`, and reserved local lanes open no ID-tree
  epoch, so nothing signed there verifies.
- **So a chainless minting root spawns chainless seats.** Fix the root once
  (give it a chain through the exchange), not every seat. Re-certification in
  place works per key; there is no bulk path.

# Client floor

aw sends `id_tree` on setup-key init (`init_apikey.go`) from aw-v1.36.53; the
first release candidate carrying it is aw-v1.36.52-rc.1, and earlier releases
send none. Use this floor when reasoning about which clients can create a
chained identity on that path.

# Why it matters

A design that expects signing at `init --new-team`, or expects automatic
provisioning to establish the first chain, will produce chainless agents
without any error. That matters most where admission requires a chain: see
[new-product admission requires a creator-signed chain](/aweb-protocol-expert/decisions/new-product-admission-requires-a-creator-signed-chain.md).
The repository's docs say only that the OATS spawn is unchanged.

Checked by the harvester at aweb main f7a5b9ccb:
`cli/go/cmd/aw/team_invite_attribution.go` `prepareTeamInviteAuthority`
returns no child link when there is no chain and no stable ID;
`cli/go/cmd/aw/init_local.go` names the implicit domain `local`;
`docs/id-certificates.md` says skip-DNS and reserved local lanes establish no
tree authority; the `--as-root` flag and the `id parent request`/`import`
commands exist; `git grep` per tag finds `id_tree` in `init_apikey.go` at
aw-v1.36.52-rc.1 and aw-v1.36.53 but not at aw-v1.36.51 (commit 3a88ea92d).
The observation that the specific root had no chain is the source's, from that
deployment. Hosted Cloud creation behaviour is outside this base.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-oss-classify, 2026-11-27; notes/oats-seats-chainless-because-root-is.md.

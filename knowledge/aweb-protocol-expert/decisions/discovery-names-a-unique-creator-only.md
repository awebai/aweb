---
type: Decision
title: Discovery names a unique creator only
description: When the creator signs a child's parent certificate, authority discovery may use a single qualifying creator and must print it, while several qualifying identities require the operator to choose; directory order never picks the creator, and refusing every discovered creator was rejected. Ruled 2026-11-18; implemented on a branch, not on main.
tags: [decision, aw-cli, identity, parentage, creator, discovery, team-extend]
timestamp: 2026-11-18
---

Ruled by the operator on 2026-11-18 under task aweb-adjd.1. The acceptance is
**source-reported**: it was relayed to the source by the OSS coordinator by
mail, and no independently readable record of it exists.

# Why this is a parentage question

When the creator signs the child's parent certificate, choosing the creator
decides who the new child answers to. That is a different question from
whether a candidate is allowed to authorize the membership. Several same-team
identities may all be able to sign the membership request, and they are still
not interchangeable as creators.

# Decision

- Discovery (for example in `aw team admin extend`) may use a creator it finds
  only when exactly one qualifying identity exists for the requested team. It
  prints the identity and home it chose.
- When several qualifying identities are found, the command lists them and
  refuses before writing anything. The operator selects one explicitly.
- Directory order, or any other filesystem sort, never chooses the creator.

This refines how a creator is selected. It does not supersede
[identity selection is one precedence rule](identity-selection-is-one-precedence-rule.md),
which decides the acting principal; this decision adds no fallback to it. It
also changes no invite membership rule.

# Rejected

- **Borrowing the lexicographically first qualifying home.** A deterministic
  sort is repeatable, but it does not express who the operator meant the child
  to answer to.
- **Refusing every discovered creator.** That would remove the documented
  team-directory convenience without resolving any ambiguity, because one
  candidate is not ambiguous.

# Status

Implemented on the source's review branch (commit 7d01511dd), where the source
reports that the native child-parent and ambiguous/swap controls pass. On aweb
main, `docs/team-extend-sot.md` still describes borrowing the lexicographically first
qualifying home, so main still has the rejected behaviour. No release and no
paired hosted result is claimed.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-signer-membership, 2026-11-18; notes/creator-discovery-requires-an-unambiguous-identity.md.

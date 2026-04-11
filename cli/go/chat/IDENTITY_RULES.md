# Chat Identity Rules

This file is the source of truth for CLI chat identity matching and display.

## Identity Tiers

Strong identities:
- stable DID: `did:aw:...`
- current DID: `did:key:...`
- full address: `namespace/handle`

Weak identities:
- bare alias / bare handle: `handle`

## Core Rules

1. Strong identities win over weak identities.
2. Weak aliases are only a fallback when no strong identity is available.
3. Bare aliases must fail closed on ambiguity.
4. Address and DID rows for the same participant should collapse to one concrete identity after resolver normalization.
5. Sparse alias-only rows must not create ambiguity by themselves when a richer row already identifies the same participant.

## Selector Matching

Session and pending lookup use these rules:
- explicit DID or address targets may match participant rows through normalized identity equivalence
- bare alias targets may match a participant only when the alias resolves to exactly one concrete participant
- if multiple concrete participants match a bare alias, lookup must fail closed

## Event Matching

Incoming chat events are matched to participants in this order:
1. `from_address`
2. `from_stable_id`
3. `from_did`
4. `from_agent`

For the first three fields, matching must stay on the same strong tier first.
If strong sender identity fields conflict with concrete participant context, matching must fail closed rather than falling back to weak alias/handle matching.
Weak alias matching is only allowed when the event does not carry strong sender identity fields, or when no concrete participant context exists to contradict the alias.

## Display Labels

Preferred label order is:
1. address
2. stable DID
3. current DID
4. alias

Participant-derived labels may override raw event or pending fields only when they provide a stronger identity and resolve to one participant row.

## Self Detection

Self detection uses strong identities first:
- if `stable_id` or `did` matches self, treat as self
- if strong self identities exist and the event/pending item also has a strong identity that does not match, do not fall back to alias
- only fall back to address handle or alias when neither side has a usable strong identity

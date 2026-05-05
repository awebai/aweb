# Messaging Contract Matrix

This note records the architectural checkpoint from the 2026-05-05 release
failure review. It is intentionally a contract note, not an implementation
patch.

## Assessment

The core trust model is sound, but recent implementation work drifted away from
the full contract. The failures are consistent with applying local fixes faster
than we re-grounded them against all messaging use cases.

The intended authority split is:

- `awid` owns identity, address bindings, reachability, team membership,
  certificates, and key rotation.
- `aweb` owns coordination state: mail, chat, conversations, tasks, roles, and
  workspace behavior.
- Address reachability controls first contact and discovery.
- Once a conversation exists, replies are authorized by conversation
  participation, not by re-running public address discovery.
- A persistent identity can belong to multiple teams without becoming a new
  identity.
- Bare aliases are local to the active team/namespace. Cross-namespace
  communication uses an address or an explicit selector.

This is necessary complexity for BYOIDT, hosted identities, non-public
addresses, key rotation, and multi-team membership. The main architectural smell
is duplicated authority: some routes historically inferred visibility from mail
rows, while conversation continuation relies on `conversation_participants`.
Conversation participants must be the authority for existing conversations.

## Use Cases

The release gate must cover these cases for both mail and chat where applicable:

1. Same-team bare alias.
2. Same-team full address.
3. Same-team alias-first, then full-address continuation.
4. Cross-team same namespace with explicit team selector.
5. Cross-namespace public address first contact.
6. Non-public address first contact with a valid team certificate.
7. Non-public address first contact without authorization fails closed.
8. Reply by existing `conversation_id` after first contact, even if the address
   is hidden.
9. Direct `did:aw` send, independent of address reachability.
10. Key rotation preserves conversation continuity.
11. Ephemeral local identity: team-local alias only.
12. Persistent identity in multiple teams: active team selects sender context.
13. Existing identity added to another hosted or BYOIDT team without cloning the
    identity.
14. Duplicate aliases across teams require explicit address or team context.
15. Hosted custodial identity follows the same messaging contract.
16. Local pin fallback is only for already-known peers, not address authority.
17. Mismatched recipient bindings fail closed.
18. Duplicate active one-to-one conversations are rejected or cleaned up.
19. Closed or expired conversations cannot be continued.
20. Conversation listing shows conversations where the actor is a participant.

## Current Documentation Anchors

- `docs/awid-sot.md`: identity, address, team certs, reachability.
- `docs/aweb-sot.md`: aweb coordination and identity-scoped messaging.
- `docs/identity-messaging-contract.md`: messaging authority split and direct
  address send protocol.
- `docs/contributing.md`: release validation expectations.
- `scripts/e2e-oss-user-journey.sh`: executable OSS messaging/reachability
  matrix.

## Release Discipline

Do not ship messaging or identity changes unless the affected rows above are
covered by focused tests and the release gate runs against the exact artifact
that will be consumed downstream. For cloud integration, AC must validate
against the published or locally installed aweb artifact intended for release.

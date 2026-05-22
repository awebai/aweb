# Messaging Contract Matrix

This note records the architectural checkpoint from the 2026-05-05 release
failure review. It is intentionally a contract note, not an implementation
patch.

## Assessment

The core trust model is sound, but recent implementation work drifted away from
the full contract. The failures are consistent with applying local fixes faster
than we re-grounded them against all messaging use cases.

The intended authority split is:

- `awid` owns identity, address bindings, route/delivery metadata, team
  membership, certificates, and key rotation.
- `aweb` owns coordination state: mail, chat, conversations, tasks, roles, and
  workspace behavior.
- Address resolution controls first contact routing; delivery authorization is
  the recipient's aweb `inbound_mode`: `open` (**All**) or `contacts_only`
  (**Contacts only**). Team certificates do not create routes, resolver
  visibility, or delivery exceptions; `contacts_only` means exact active
  contacts only.
- Once a conversation exists, replies are authorized by stored conversation
  participation and route state, not by re-running address discovery.
- A global identity can belong to multiple teams without becoming a new
  identity.
- Bare aliases are local to the active team/namespace. Cross-namespace
  communication uses an address or an explicit selector.

This is necessary complexity for BYOIDT, hosted identities, address routing,
key rotation, and multi-team membership. The main architectural smell
is duplicated authority: some routes historically inferred visibility from mail
rows, while conversation continuation relies on `conversation_participants`.
Conversation participants must be the authority for existing conversations.

## Use Cases

The release gate must cover these cases for both mail and chat where applicable:

1. Same-team bare alias.
2. Same-team full address.
3. Same-team alias-first, then full-address continuation.
4. Cross-team same namespace with explicit team selector.
5. Cross-namespace address first contact with `inbound_mode=open`.
6. Cross-namespace address first contact with `inbound_mode=contacts_only` and
   an exact active identity contact.
7. Cross-namespace address first contact with `inbound_mode=contacts_only` and
   only same-team membership or a team certificate, but no exact active contact,
   fails closed.
8. Cross-namespace address first contact without a valid route or required
   exact contact fails closed.
9. Reply by existing participant route after first contact, without re-running
   address discovery.
13. Bare external `did:aw` first contact fails closed; stored-route continuation works.
14. Key rotation preserves conversation continuity.
15. Local identity: team-local alias only.
16. Global identity in multiple teams: active team selects sender context.
17. Existing identity added to another hosted or BYOIDT team without cloning the
    identity.
18. Duplicate aliases across teams require explicit address or team context.
19. Hosted custodial identity follows the same messaging contract.
20. Local pin fallback is only for already-known peers, not address authority.
21. Mismatched recipient bindings fail closed.
22. Duplicate active one-to-one conversations are rejected or cleaned up.
23. Closed or expired conversations cannot be continued.
24. Conversation listing shows conversations where the actor is a participant.

## Current Documentation Anchors

- `docs/awid-sot.md`: identity, address, delivery metadata, team certs, and
  legacy reachability compatibility/audit state.
- `docs/aweb-sot.md`: aweb coordination and identity-scoped messaging.
- `docs/identity-messaging-contract.md`: messaging authority split and direct
  address send protocol.
- `docs/contributing.md`: release validation expectations.
- `scripts/e2e-oss-user-journey.sh`: executable OSS messaging and inbound-mode
  matrix.

## Release Discipline

Do not ship messaging or identity changes unless the affected rows above are
covered by focused tests and the release gate runs against the exact artifact
that will be consumed downstream. For cloud integration, AC must validate
against the published or locally installed aweb artifact intended for release.

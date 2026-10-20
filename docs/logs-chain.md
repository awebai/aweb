# The logs chain: commitments, event hashes, receipts and checkpoints

Status: **specified experimental public contract, not yet shipped**. Owner: the
aweb OSS hooks lane (aweb-acgh.16.21). This document is the source of truth for
the bytes logs commits to and signs. Its vector is
`docs/vectors/logs-chain-v1.json`. The Python implementation in
`naapp/logs/src/aweb_logs/chain.py` and `verify.py` regenerates it byte for
byte. The design and its rationale are in
[the audit substrate design](design/audit-substrate.md), §B3 and §B6.

## What the chain proves, and what it does not

A producer's signature proves who emitted an event. The chain proves that,
inside logs, nothing was later dropped, reordered or altered. Once a
checkpoint or a receipt has left logs, anyone holding it can detect a later
rewrite by anyone who does not control logs' key. Logs cannot stop an operator
that controls its key from rewriting the whole chain before any witness exists.
It also cannot stop a compromised producer from signing false events. The
remedies are witnesses (producer receipts, checkpoints the owner exports,
self-hosting) and, later, external anchoring.

## Encoding rules

Every hashed or signed object below is encoded as **strict canonical JSON**,
the hook event rules (`aweb_naapp.hooks.strictjson`, `cli/go/strictjson`):
sorted keys, no insignificant whitespace, printable ASCII strings with only `"`
and `\` escaped, safe-range integers, no floats and no `null`. An optional
field is absent, never `null`.

| Value | Spelling |
| --- | --- |
| a digest (`*_hash`, `*_sha256`, `content_commitment`) | 64 lowercase hex characters of a SHA-256 |
| a time (`received_at`, `created_at`, `issued_at`) | UTC to the millisecond, `YYYY-MM-DDTHH:MM:SS.mmmZ`, the hook event time spelling |
| a signature | detached Ed25519: exactly 86 characters of the standard base64 alphabet, no padding, zero trailing bits |
| `salt` | 32 bytes; in the vector, unpadded base64url |
| `team_id`, `logs_origin`, `kid`, `did_key`, `event_id` | the hook envelope's patterns for a team id, an origin, a kid, an Ed25519 `did:key` and a UUID |

`||` below is byte concatenation. Each prefix is ASCII and ends in one newline.

## A team's chain

Logs keeps one chain per team and **chain epoch**. Epochs count from 1. Within
an epoch, `team_seq` counts events from 1, with no gaps, and logs assigns it
under a row lock on the team's chain head, so two events never share a
sequence number.

### Genesis

    genesis_hash = SHA-256("aweb.logs-genesis/1\n" || canonical(genesis))

`genesis` is `{team_id, chain_epoch, logs_origin, created_at}`. In every epoch
after the first it also carries `previous_checkpoint_sha256`: the SHA-256 of
the signing bytes of the previous epoch's final checkpoint. That is how a new
epoch, for example after a move to a self-hosted logs, records where the
previous one ended. The first epoch never carries it.

### An event

For each event logs draws a fresh 32-byte `salt` and stores it with the
event's content: the producer's envelope signing bytes and signature.

    content_commitment = SHA-256("aweb.logs-commit/1\n" || salt || signing_bytes || signature)

`signature` here is the raw 64-byte signature. The salt and the signature have
fixed lengths, so the three parts split one way only.

    event_hash = SHA-256("aweb.logs-chain/1\n" || canonical(link))

`link` is exactly `{chain_epoch, team_id, team_seq, prev_event_hash,
received_at, hook, producer_origin, content_commitment}`:

- `prev_event_hash` is the previous event's `event_hash`, or `genesis_hash`
  for `team_seq` 1;
- `hook` is the envelope's hook;
- `producer_origin` is the envelope's `producer.origin` for a `core` or `app`
  producer, and `client:` followed by `producer.certificate_id` for a `client`
  producer, which has no origin. Renewing a member's certificate changes its
  id, so a renewed client appears under a new `producer_origin`: it is a new
  credential.

The link fields are the event's **skeleton**. Retention and erasure purge the
content (signing bytes, signature and salt) and every projection, index and
cache derived from it. They keep the skeleton, so the chain still verifies
across a purged event. Deleting the salt makes the commitment unlinkable to
guessed content.

## Signed artefacts

Logs signs with its own key. Its v2 manifest declares that key in `app_keys`
with the purposes `logs-receipt`, `logs-checkpoint` or both. One kid may carry
both. Only logs and the verifiers of its artefacts consume these purposes. A
verifier accepts an artefact only from a key the logs manifest declares for
that artefact's purpose.

### Receipt, `aweb.logs-receipt/1`

    {"v": 1, "type": "aweb.logs-receipt", "team_id", "event_id", "chain_epoch",
     "team_seq", "event_hash", "received_at", "logs_origin", "kid", "did_key"}

The signing bytes are `aweb.logs-receipt/1\n` followed by its canonical JSON.
Logs returns a receipt for every event it appends, and returns the same receipt
again for a duplicate delivery: the same `event_id` with the same bytes. Other
bytes under a known `event_id` append nothing and are kept as a conflict fault
(the digest of the refused bytes, never the bytes). A purged event's bytes are
gone, so a redelivery of it cannot be compared and returns its receipt. A receipt commits to the whole chain prefix up
to its event, so every producer that keeps one is an independent witness of
the chain.

### Checkpoint, `aweb.logs-checkpoint/1`

    {"v": 1, "type": "aweb.logs-checkpoint", "team_id", "chain_epoch",
     "team_seq", "event_hash", "issued_at", "logs_origin", "kid", "did_key",
     "previous_checkpoint_sha256"}

The signing bytes are `aweb.logs-checkpoint/1\n` followed by its canonical
JSON. `team_seq` and `event_hash` are the chain head it witnesses. A checkpoint
of an empty epoch has `team_seq` 0 and the epoch's `genesis_hash`.
`previous_checkpoint_sha256` is the SHA-256 of the signing bytes of the
epoch's previous checkpoint; the first checkpoint of an epoch has none. Logs
issues checkpoints periodically while events arrive and on demand, and the
owner can export them.

The receipt and checkpoint prefixes are unique to logs, so neither verifies as
any other signed aweb object, and no other object verifies as either.

## Verifying a chain

`verify` reads one team epoch's stored events in `team_seq` order, with any
receipts and checkpoints it is given, and reports:

- **`intact`**: true when every present event links, every retained content
  matches its commitment and verifies under its producer key, no event is
  missing, and no artefact given is contradicted. A purged event does not make
  the chain broken.
- **`first_break`**: the first `team_seq` that fails, with its reason. Each
  event is checked in this order, which is normative, and reports only its
  first fault:
  - `sequence_duplicate`: another stored event already holds this `team_seq`;
  - `wrong_chain`: the event's `team_id` or `chain_epoch` is not the epoch's;
  - `prev_hash_mismatch`: `prev_event_hash` is not the previous event's hash
    (or `genesis_hash` at `team_seq` 1);
  - `event_hash_mismatch`: the stored `event_hash` is not the hash of its link;
  - `content_missing`: the content is gone but no purge act is recorded;
  - `commitment_mismatch`: the retained content does not hash to
    `content_commitment`;
  - `provenance_invalid`: the retained envelope does not verify under the
    producer key recorded with it, or belongs to another team;
  - `skeleton_mismatch`: the event's `hook` or `producer_origin` is not the
    retained envelope's.
- **`missing`**: inclusive `[from, to]` ranges of absent sequence numbers. A
  link across a gap cannot be checked, so it is not reported as a break.
- **`purged`**: inclusive `[from, to]` ranges of events whose content is
  purged, each with the act that purged it, an opaque reference reported as
  stored.
- **`contradicted`**: each receipt or checkpoint given that the chain
  contradicts, by its position in the input, with its reason:
  `signature_invalid` (not signed by the logs key it names, or that key is not
  the expected one), `wrong_chain` (another team, epoch or logs origin),
  `not_in_chain` (its sequence number is not present), `hash_mismatch` (the
  chain holds a different `event_hash` at its sequence number) or, for a
  receipt, `event_mismatch` (the event at its sequence number was received at
  another time or, while its content is retained, has another `event_id`).
  These checks run in that order, and each artefact reports its first. A
  checkpoint whose `previous_checkpoint_sha256` names no checkpoint given is
  not contradicted.

`verify` reports the producer and hook sequence gaps inside binding intervals,
and conflicting deliveries, from logs' records of bindings and faults. Those
are not part of this pure chain check or of its vector.

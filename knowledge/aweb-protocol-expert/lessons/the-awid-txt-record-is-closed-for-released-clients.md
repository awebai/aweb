---
type: Lesson
title: The _awid TXT record is closed for released clients
description: Released aw (1.36.58, 1.36.59) parses _awid TXT strictly and refuses any key beyond awid, controller and registry with sender_registry_discovery_failed, so a new key breaks every released client's discovery for that domain; the Python and Go lenient parsers ignore unknown keys and hide this, so check every released parser before extending a public record.
tags: [lesson, federation, dns, discovery, compatibility]
timestamp: 2026-11-28
---

`parseStrictFederationTXT` in the aw CLI accepts only the keys `awid`,
`controller` and `registry`. Any other key, a duplicate key or an empty value
refuses with `sender_registry_discovery_failed`. Released aw 1.36.58 and
1.36.59 carry the same check. Adding a field to `_awid` TXT (for example an
issuer condition) would therefore break federation discovery for that domain
in every released client.

The Python awid parser and the Go `ParseAWIDTXTRecord` ignore unknown keys. A
change checked only against them looks safe.

# How to apply

- Before extending any public record, find every released parser of it, not
  the first one, and check what each does with an unknown field.
- Treat the `_awid` TXT key set as closed. New namespace facts go in a signed
  registry record instead, as
  [the issuer personhood condition](/aweb-protocol-expert/decisions/issuer-personhood-condition-is-a-namespace-record.md)
  does.

This applies
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-adyx13-hw-personhood, 2026-11-28; notes/awid-txt-is-closed-for-released-clients.md. The harvester confirmed the strict key check in `cli/go/awid/federation_authority.go` on main at fbfa65f22; the released 1.36.58 and 1.36.59 sources are source-reported.

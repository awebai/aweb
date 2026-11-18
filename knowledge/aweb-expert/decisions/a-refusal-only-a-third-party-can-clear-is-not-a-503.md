---
type: Decision
title: A refusal only a third party can clear is a 4xx, never a 503
description: Choose a refusal's status by who can fix it and whether waiting helps; a condition only someone else can clear is a 4xx with a code and a sentence naming who must act, never a 503, which clients and aw retry, and 503 authority_unavailable stays for transient authority failures.
tags: [decision, naapps, http-status, refusals, retries]
timestamp: 2026-11-18
---

Decided on 2026-11-18 in task aweb-adje.16.2. The egress-refused team server
(see [tenant-chosen URLs go through egress](/aweb-expert/decisions/tenant-chosen-urls-go-through-egress-with-an-exact-origin-allowlist.md))
first shipped as `503 team_server_not_allowed`, justified by "callers already
handle 503 here". The security reviewer noted the condition was permanent and
would be retried uselessly, the naapps coordinator required a non-retryable
status, and it became `403 team_server_not_allowed`.

# Decision

- Pick the status by **who can fix the condition** and **whether waiting
  helps**. Cite the document line that defines the status you chose.
- A refusal that only a third party can clear (here the team's controller
  republishing its server) is a 4xx with a distinct code and a sentence that
  names who must act.
- It is never a 503. Clients and aw retry 503s, and a distinct code alone does
  not stop the retry.
- `503 authority_unavailable` stays for transient authority failures:
  unreachable, mismatched or no longer fresh (the `InstallationRefused` table
  in `docs/app-registry.md`).

# Rejected

- **"Callers already handle 503 here."** Convenient, and it leaks a permanent
  condition into retry loops. It shipped once and had to be corrected after
  review.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-egress, 2026-11-18; notes/permanent-refusal-is-not-503.md.

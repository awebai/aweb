---
title: "Agent skills"
description: "Task-specific plain-text playbooks for agents using folio."
eyebrow: "Fetch before acting"
---

folio is an aweb anapp: an agent-native app on the [aweb.ai hub](https://aweb.ai).
Agents authenticate with [AWID](https://awid.ai) team certificates and should
fetch the relevant skill before acting so requests match the folio API contract.

Available skills:

- [`/skills/create-from-template/SKILL.md`](/skills/create-from-template/SKILL.md) — create or append documents from built-in pitch, memo, and metrics templates.
- [`/skills/present-to-human/SKILL.md`](/skills/present-to-human/SKILL.md) — mint, open, and revoke human presentation links.
- [`/skills/set-theme/SKILL.md`](/skills/set-theme/SKILL.md) — brand presentation pages with team colors, fonts, header/footer, and logos.
- [`/skills/team-cert-verification/SKILL.md`](/skills/team-cert-verification/SKILL.md) — verifier checklist for AWID team certificates.
- [`/skills/agent-first-app/SKILL.md`](/skills/agent-first-app/SKILL.md) — agent-first app model patterns.
- [`/skills/byot-e2e-validation/SKILL.md`](/skills/byot-e2e-validation/SKILL.md) — BYOT end-to-end validation patterns.

The compact machine-readable entrypoint is [`/llms.txt`](/llms.txt).

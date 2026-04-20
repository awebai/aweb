---
name: deploy-awid-site
description: Deploy the awid.ai landing page. Copies docs into the site static directory, merges to deploy-awid-landing branch, and pushes.
---

# Deploy awid.ai landing page

The awid.ai site is deployed via the `deploy-awid-landing` branch.
Pushing to that branch triggers the hosting platform deployment.

## Flow

1. Run the Makefile target.
   ```bash
   make release-awid-site
   ```

   This does:
   - Copies `docs/identity-guide.md` into `awid/site/static/`
   - Copies `docs/trust-model.md` into `awid/site/static/`
   - Commits if anything changed
   - Checks out `deploy-awid-landing`
   - Merges main
   - Pushes `deploy-awid-landing`
   - Checks out main

2. Verify.
   The deployment should be live within a few minutes at awid.ai.

## When to deploy

Deploy after changing any of:
- `docs/identity-guide.md`
- `docs/trust-model.md`
- `awid/site/` templates or static files

## Notes

- The site serves identity-guide.md and trust-model.md as static files
  at `https://awid.ai/identity-guide.md` and `https://awid.ai/trust-model.md`.
- The agent-guide.md is served from aweb.ai, not awid.ai. Alice
  handles the aweb.ai site deployment.
- Always push main before deploying so the site gets the latest docs.

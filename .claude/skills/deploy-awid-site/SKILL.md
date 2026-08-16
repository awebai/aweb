---
name: deploy-awid-site
description: Deploy the reviewed aweb main commit to the awid.ai static site through its dedicated landing branch.
---

# Deploy awid.ai

The site source is `awid/site/`. Its committed mirrors of
`docs/identity-guide.md` and `docs/trust-model.md` must already be current and
reviewed before deployment. If they are stale, run `make sync-awid-site-docs`,
commit the result, obtain review, and merge it normally.

After the outward production action has been authorized, run:

```bash
make deploy-site
```

The command builds the site, refuses a dirty checkout or a commit other than
the fetched `origin/main`, requires a fast-forward from the current
`deploy-awid-landing` tip, pushes the exact main SHA, and reads the remote ref
back. It does not create a commit or participate in artifact release.

Render must be configured to build `awid/site` from `deploy-awid-landing`.
After the branch advances, verify the Render deploy completed and that
https://awid.ai plus both mirrored documents serve the intended content.

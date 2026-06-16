# Aweb Anapp Product Constraints

For aweb revamp advice, treat `atext` as the public sample/reference for
third parties who want to build their own agent-native apps. Treat `folio` as
one first-party app, not as the assumed flagship. The strongest wedge may be
messages/mail/chat, but the product signal is not settled yet.

Billing should be simple and bundled: hosted apps are free up to one shared
mutation-call quota, and paid tiers raise that quota. A2A is not a special
capability gate; hosted A2A gateway operations count against the same bundled
hosted mutation quota.

Tasks should be an independent generic anapp (`tasks.aweb.ai`) because task
tracking is useful beyond software development. `dev.aweb.ai` is specifically
for developer/dev-loop workflows and may consume or embed tasks, but should
not own the generic task product.

# Mission Ctrl ↔ hosted federation live test

This is review material, not authorization to contact an external operator or
change production DNS. Run it only after the coordinator records explicit human
consent for the named identities, time window, and test messages.

## Preconditions

1. Record the Mission Ctrl and hosted concrete addresses, expected `did:aw`,
   current `did:key`, registry origins, and delivery origins without copying
   private keys or tokens into the report.
2. Confirm the hosted managed-namespace reconciler reports the exact child TXT
   value as published. Query `_awid.<hosted-child>` through both an authoritative
   nameserver and an independent recursive resolver. Both must name the hosted
   child controller and `https://api.awid.ai`; an inherited `_awid.aweb.ai`
   answer is not sufficient.
3. Resolve each address directly from its selected registry and confirm the
   foreign registry does not contain a shadow row for it.
4. Agree on unique harmless subjects/bodies, retention/cleanup expectations,
   and a stop contact. Do not use customer content.

## Consented test

1. From Mission Ctrl, send one plaintext mail and one chat to the hosted concrete
   address. Record command exit status and message/conversation IDs.
2. On hosted, confirm both items arrived and retain the recipient's verification
   verdict. Reply once in the same mail conversation and once in chat.
3. On Mission Ctrl, confirm both replies and retain its verification verdict.
4. Require verified identity continuity, the expected destination/origin, and no
   fallback to either home registry for the foreign address.

Stop immediately on an unexpected controller, registry, delivery origin,
verification verdict, duplicate delivery, or unrelated inbox data. Do not
change DNS to diagnose during the live window.

## Report

Record consent, UTC timestamps, exact public addresses/DIDs/controllers,
observed TXT answers and TTL, registry/delivery origins, message IDs, and
verification verdicts. Redact credentials and message bodies beyond the agreed
harmless fixtures. Production DNS mutation, Ben Ford contact, and broader user
testing each require separate approval.

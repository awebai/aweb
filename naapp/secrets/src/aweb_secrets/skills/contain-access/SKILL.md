---
name: contain-access
description: Stop future Secrets credential uses with a narrowly scoped revocation or the installation kill switch.
---

Read the installed app's `/reference` for the current `contain` schema and your
authority. Containment narrows access and needs no passkey. It still requires
the caller's verified identity and the appropriate Secrets role.

Choose the smallest action that covers the incident. For an owner revoking a
grant: `aw secrets contain --request_id YOUR_REQUEST_ID --action revoke-grant --target GRANT_ID`.
For an owner disabling the whole installation:
`aw secrets contain --request_id YOUR_REQUEST_ID --action disable-installation`.
Other supported targets include a secret, pending approvals, an approver or a
runner; use the manifest's enumerated actions and actual identifiers.

Check the returned state and the operational/audit record available to you.
Stopping future dispatch does not undo a request already sent or recall a
credential already delivered to a runner. Upstream credential rotation and
1Password service-account revocation remain the owner's actions outside
Secrets. Record any uncertain effects for reconciliation. Never handle the
credential value while investigating, and never treat an audit enqueue as
completed delivery to logs.

---
type: Decision
title: Local message logs are sealed to an owner log key, and agents cannot read them back
description: aw seals each line of its local mail and chat logs to the team's owner log key (an X25519 key whose public record is signed by the team controller key), so only the owner reads them back; agent read-back, sealing to the agent's own key, the owner's published E2EE key and an unprotected key file were rejected because co-located agents share one OS user. Accepted; on a branch under review, not landed.
tags: [decision, aw-cli, local-logs, e2ee, owner-log-key]
timestamp: 2026-11-13
---

**Status (2026-11-13):** accepted by the operator on 2026-11-13. The acceptance
is **source-reported**: the OSS coordinator relayed it by mail. Implemented on
branch `agents/aweb-protocol-expert-local-log-encryption` (06e21edfb), under
review and not on main. The mechanics, as built, are in `docs/configuration.md`
"Local Message Logs" on that branch.

# Decision

aw keeps two local logs of decrypted mail and chat: the per-account
communication log and the instance's interaction log. Each line of both is
sealed on its own to the team's **owner log key**, and the agent that writes a
log cannot read it back.

- The owner log key is an X25519 keypair. Its public record is signed by the
  team controller key under a domain-separated prefix. An agent host uses the
  record only after verifying it against the team key in its own team
  certificate.
- The private key lives only on the owner's machine, behind a passphrase.
- The operator decided three points:
  - **Only the owner reads the logs back.** The agent loses its local recap and
    `aw log`; its history stays available from the server.
  - **With no key installed, the logs stay plaintext** and `aw doctor` warns.
    Refusing to log without a key was the alternative offered; the operator
    chose not to change the default for everyone without a key.
  - **Existing plaintext is sealed in place** on the first sealed write, with
    no secure-delete promise: old plaintext can survive in free disk blocks,
    snapshots and backups.
- An installed record that does not verify **stops logging**. It never falls
  back to plaintext.

# Why

All agents in a team container run as one OS user. Any key an agent can use to
read its own log can be read by every co-located agent, so agent read-back is
plaintext in practice. Public-key sealing gives write-only logs: the local
archive, its copies and backups, and a later disk compromise expose only
ciphertext.

# Rejected alternatives

- **Agent read-back, including sealing each line also to the agent's own E2EE
  key.** Sibling agents can read that key, so it is no better than plaintext.
- **The owner's published E2EE identity key.** A hosted custodial human's key is
  held by the hosting service, and an owner may have no self-custodial aw
  identity.
- **An unprotected private-key file in the owner's aw directory.** Agents on the
  owner's laptop run as the owner and could read it. The key needs a passphrase;
  the OS keychain holding an encrypted backup, as for the human key, gives that.

# Limits a future instance must keep

- **Sealed lines are confidential but not authenticated.** Anyone who can write
  the file can seal a line to the public key. Owner-side readers treat every
  entry as untrusted and escape terminal control sequences.
- **Sealing does not isolate co-located agents.** They can still read each
  other's `.aw` keys and pull each other's mail from the server. Isolation needs
  one OS user per agent or a process that holds the keys.
- **Grant seats cannot verify the record.** A grant home carries no team
  certificate. This is open.

The rule applies to any local record of decrypted content an aw agent keeps.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-local-log-encryption, 2026-11-13; notes/local-logs-sealed-to-owner-key.md, notes/acyh-design.md. Verified by the harvester on 2026-11-13: the branch head 06e21edfb exists, its "Local Message Logs" section matches the decision, and it is not on main.

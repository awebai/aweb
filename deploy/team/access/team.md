# What the team should know about who can read its data

For the team's owner and members, people and agents.

## The operator

Whoever operates the machine the deployment runs on can read:

- **your mail and chat**, in aweb's database, unless the sender used `--e2ee`
  between self-custodial identities;
- **every secret value stored in Secrets**, with Secrets' database and the
  custody key, which the operator holds;
- **every event Logs keeps**, and, holding Logs' chain key as well, rewrite
  that history so that it verifies;
- **every agent's session transcripts and seat keys**, on the agents' volume.

If another organization operates your deployment, that organization is the
operator. `deploy/team/access/operator.md` lists each artifact and what it
gives.

## The agents of one container

Agents in one container run as one operating-system user, so they form one trust
group: any agent can read every seat's key and act as any seat, read the harness
login, and read the other agents' transcripts and interaction logs.
A seat's identity tells you which seat acted, not which agent.
`deploy/team/access/agents.md` lists what they can and cannot reach.

## The audit log

Logs records the events its producers send. In this bundle those are Secrets
(secret uses and governance acts) and Logs itself (its own owner acts); mail,
chat, tasks and the agents' commands are not among them. No agent's commands
are recorded. An agent could submit agent-reported events signed with any seat
key in its container, and Logs would show them as that seat's claims, not as
observed facts.

## Your owner authority

Once the protected act has moved the team's controller key into the signer, no
person or agent holds it. The signer then performs one operation,
`human-role.revoke`, approved by a person in the browser. Admitting or removing
a member needs the controller key, so it is not possible until the signer's
catalog implements it (`OPERATIONS.md`, "Removing an agent, a service or an
owner").

## The registry and the model provider

`deploy/team/access/registry-and-provider.md`.

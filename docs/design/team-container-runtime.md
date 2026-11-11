# Team-container runtime for OATS agents (aweb-acwd.17)

Status: BUILD AUTHORIZED for the bounded Hetzner slice (Juan, 2026-11-10,
servers bb6a1b80): one team container with two admitted seats, on the existing
lab host, plus up to four further sequential reviewers for oats#1786 part 2.
Nothing is deployed yet. Managed-Kubernetes acceptance and the full journey are not covered.

Editor: oats-expert-juan (acwd.17 owner). Sections are marked with the owner
who supplied them. "HYPOTHESIS" marks a claim the first build checks first.
"Source:" cites the code a claim rests on.

## 1. Goal and scope

Agents run in a controlled container per team (trust group), with one process
per agent. Two first-class targets share one image and one configuration and
security contract:

- **Hetzner**: Docker Compose, operated by us.
- **Managed Kubernetes**: Helm on an organisation's own cluster deploying through GitOps, validated on such a cluster.

A pass on one target does not qualify the other. The existing lab host-UID
evidence is intermediate and qualifies neither.

Out of scope:
- per-agent containers (optional later);
- banning laptop agents (they stay supported);
- hosting customer resources in this stack;
- inheritance-based unattended admission (acwd.13/.16), which is needed for
  the finished journey but not for the first fixed two-agent proof;
- video, until the complete user journey works.

## 2. Common agent image (OATS)

**Baked at build time.**
- OS: debian-slim pinned by digest, plus tmux, git, openssh-server,
  ca-certificates.
- Node 22.
- CLIs, each pinned:
  - `@awebai/oats`;
  - `@awebai/aw`, installed with `--allow-scripts=@awebai/aw`;
  - `@anthropic-ai/claude-code`.
- Only Claude is enabled in the first slice. Another harness is added only
  together with its own auth section in section 7.

**User.**
- One non-root `agent` user with no sudo. Its uid is set at run time and is
  not baked into the image: 20001 on Hetzner (section 4.2), the cluster's
  value on Kubernetes.
- `HOME=/state/home`.

**Filesystem.**
- The root filesystem is read-only. `/tmp` (and `/run` if sshd needs it) are
  tmpfs.
- `/state` is the one writable volume. It holds:
  - the deployment at `/state/deploy`, with the instance homes under it;
  - HOME, which holds the OATS kernel cache, the git clones of package pins
    and aw state;
  - the per-agent seats (section 6.1);
- `/work` is optional, for checkouts kept apart.

**sshd** (an optional entry point, on only where the target uses the SSH
route):
- runs as `agent` on port 2222;
- keys only (`PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
  `AllowUsers agent`);
- `AuthorizedKeysFile /etc/agent-ssh/authorized_keys`, which the operator
  mounts read-only;
- host keys are generated on first start into `/state/ssh`.

**Runtime writes that OATS supports.** Read-only root does not remove these,
because each one writes under HOME or `/state`:

| Operation | Where it writes | In a read-only-root container |
|---|---|---|
| package/soul sync (git clones of `oats-lock.json` pins) | `$HOME/.oats`, the deployment | works; needs the forwarder to allow the git host (section 4.1) |
| spawn, instance homes, events | `/state/deploy` | works |
| Claude user settings and per-user plugins | `CLAUDE_CONFIG_DIR` (section 7) | works; plugin installs from a marketplace need its host on the allowlist |
| aw identity state | the seat and home `.aw` directories | works |

**Global npm installs** (`npm install -g`) write to `/usr/local` and fail on a
read-only root. These are the five consumers in the installation-profile
audit (oats#1784):
- the getting-started skill;
- `/oats-upgrade`;
- `lib/pi-bridge.mjs:102`;
- `lib/servers.mjs:1506` (`--install-oats`);
- oats-aweb `--install-aw`.

Disposition: in the container, the CLIs are upgraded by a new image tag only.
Today those five fail with npm's own EACCES. Gap O3 (oats#1784) makes them
refuse with a message naming the image-tag route. OATS connects without
`--install-oats`.

**Derived customer image.** A reviewed build file `FROM` the common image that
adds OS packages and tools only. It never contains credentials.

## 3. Configuration contract (OATS; same inputs for Compose and Helm)

Plain values only. No credential is ever set in env, a compose file, a
ConfigMap, a Helm value or mail.

| Input | Use | Enforced by |
|---|---|---|
| deployment source (repo URL + commit) | cloned into `/state/deploy` at first start; soul pins from its `oats-lock.json` | acceptance checks the lock commit |
| aweb / AWID endpoints, team id | the team the agents belong to | allowlist entry |
| operator SSH public key | SSH route only; a mounted read-only file | mount list |
| resource limits | pids, memory, cpu | runtime flags |
| approved mounts | an explicit list; empty by default | Compose/pod spec; acceptance diffs `docker inspect` / pod YAML against it |
| egress destination list | forwarder/resolver allowlist; never given to the agent | section 4.1 / 5 |
| harness launch env | literal, non-secret values only, e.g. `CLAUDE_CONFIG_DIR` | OATS launch config |

**Bootstrap material** is placed by a human or the operator and never travels
through an agent, mail or a config file:
- the agent seats (section 6.1);
- the team login (section 7).

**Launch and lifecycle (OATS).**
- The operator runs the existing OATS route:
  1. `oats server connect`;
  2. `oats spawn <soul> --server <id> --preview`, then the apply;
  3. `oats status --server` and the tmux viewer;
  4. `session restart` and `retire`.
- Container lifecycle (up, down, upgrade by tag) belongs to Compose or
  Kubernetes. `/state` persists across upgrades.
- The session-resume sweep runs outside any harness sandbox. A sandbox with
  its own PID namespace inside the container reads a different PID 1, records
  a boot of its own and so starts more resumes (oats#1792). Container start,
  stop and resume gaps: oats#1789.

## 4. Hetzner: Compose runtime (Hestia 898b84cf, relayed by aweb 3714676b)

Status: section 4 was ACKed by Hestia at 8b86e9ca (1607c7b0). Section 4.1 is
revised here for servers' transport point (ba83fafb), so it needs her
re-read.

### 4.1 Network: a container profile, separate from the host-UID profile

The host profile's nft rules match `meta skuid` on host OUTPUT. They do not
apply to packets from a container's own network namespace. So the container
needs a profile of its own, which reuses only the allowlist file
(`allow-runtime.map`) as its single source.

**Transport (how an agent reaches an allowed host).** The forwarder is an
endpoint, not a router, and the agent needs no proxy settings and no
privilege. Two parts make it work:

1. **The agent's resolver.** Docker's `--dns` points the agent at a resolver
   on the forwarder. For an allowlisted name, the resolver answers with the
   forwarder's own IP on `agents`. For any other name it answers NXDOMAIN, and
   it never forwards a query upstream.
2. **The TLS connection.** The client opens an ordinary TLS connection to
   that IP on 443. nginx `stream` with `ssl_preread` reads the SNI and the
   map. For an allowlisted SNI, nginx resolves the real name with its own
   resolver on the egress side and splices the TCP stream to that host on
   443. Any other SNI is closed. TLS stays end to end between the agent and
   the real host; nginx never terminates it.

This is not an HTTP CONNECT proxy, and it needs none.

**Limits of this transport.**
- Only TLS with SNI on port 443 gets out.
- git must use https, not ssh.
- Any client that ignores system DNS fails closed.

A connection that arrives with SNI X can only ever reach X. The client sees
the real server certificate.

**Why the agent cannot bend the route** (Hestia 3985f438, T2–T4).
- **No route out.** The `agents` network is `internal: true`, so the agent's
  routing table has the `agents` subnet and no default route. A direct IP,
  including an allowlisted host's real IP, gets ENETUNREACH before any
  filtering.
- **No network privileges.** `--cap-drop=ALL` removes NET_ADMIN (no route or
  address changes) and NET_RAW (no raw packets). no-new-privileges blocks
  regaining them.
- **The forwarder is not a router.** It sets `net.ipv4.ip_forward=0` in its
  own namespace; the build asserts it.
- **IPv6** is off on `agents`.
- **DNS.**
  - The forwarder's resolver is authoritative-only: a fixed zone, no
    recursion, no upstream.
  - The agent's `/etc/resolv.conf` is a read-only bind mount that names only
    the forwarder.
  - HYPOTHESIS, check 2: whether Docker's embedded resolver forwards to
    `--dns` servers on an internal-only network. The mount avoids depending
    on it.
- **Host-local services.**
  - HYPOTHESIS, check 3: the internal bridge may still carry a host gateway
    IP, which would expose host services bound to 0.0.0.0 (sshd, published
    ports) through host INPUT.
  - Fix, either way: a host nft input chain that rejects new connections
    from the `agents` bridge, with a named counter. Established replies
    (for the operator's ProxyJump) stay allowed.

**Host side of the forwarder.** A small nft chain keyed on the forwarder's
egress bridge interface:
- allows tcp 443 to public addresses, plus SELF4:443;
- rejects deny4 (rebinding of an allowlisted name);
- keeps named counters.

Only the allowlist file is reused from the host profile. None of the checks
rely on host OUTPUT or skuid enforcement.

**HYPOTHESES.**
- A hairpin from the forwarder to the host's public 443 (Caddy) works through
  Docker's DNAT.
- Claude Code, git, gh and aw all send SNI and use system DNS. Each is checked
  in acceptance.

### 4.2 UID and host directories

Without user namespaces, a container uid *is* the host uid. uid 10001 owns the
lab3 service keys, so the agent runs as **20001**.

- Host directories: `/srv/oats-team/<team>/{state,work}`, owned `20001:20001`,
  mode 0700.
- They are not under `/home/oatsagent` and not under `/etc/aweb-lab3`.
- The team login: `/srv/oats-team/<team>/login/`.
  - Files are `root:20001`, mode 0440.
  - Mounted read-only at `/etc/agent-login/` into that team's containers
    only.
  - The provisioner decides mounts, so it enforces "never across teams"
    there (section 7).

### 4.3 Operator access

- **Authorized keys.** `authorized_keys` is bind-mounted read-only from a
  root-owned 0644 host file. It is never baked into the image and never put in
  `/state`, which is agent-writable.
- **Reaching sshd.** sshd has a fixed `--ip` on `agents`, and the operator
  uses ProxyJump through the host's provisioner account to reach it.
  - HYPOTHESIS: Docker does not publish ports from internal networks.
  - HYPOTHESIS: the host reaches the internal network's containers.
  - Fallback: an ssh stream listener on the forwarder, used as a ProxyCommand.
  - No tailnet.
- **Disclosed: who can reach sshd.** The ProxyJump account is the provisioner
  principal (P1), so anyone who can reach ip:2222 that way is already root on
  the host. sshd adds no new principal.
- **Disclosed: host keys.** The agent can read the sshd host keys in
  `/state/ssh`. That is inside the trust group.

### 4.4 Launch flags

OATS's list:
- `--user 20001`;
- `--cap-drop=ALL`, `--security-opt no-new-privileges`;
- `--read-only`;
- not privileged; no `docker.sock`; no host HOME.

Hestia adds:
- `--pids-limit`, `--memory`, `--cpus`;
- the default seccomp and AppArmor profiles, kept;
- `--tmpfs /tmp:rw,nosuid,nodev` (and `/run` if needed);
- `--network agents` only, and never any lab3 or default network;
- `--dns` set to the forwarder's resolver;
- no `--add-host`.

### 4.5 Review and run route

`provision.sh team-container <ACTION>` uses a bundle `team-container/`:
- `compose.yaml`, the reviewable equivalent of the run flags, which
  `docker inspect` is diffed against;
- the forwarder (nginx and the resolver);
- the host nft chain;
- the host directories and `authorized_keys`.

Actions: preflight, install, up, accept, rollback, each with a prior-state
record and an exact revert.

Order of work:
1. The bytes go to Athena for review, then her ACK.
2. Juan's go (given 2026-11-10 for the bounded Hetzner slice).
3. The run, then the qualification receipt.

The host egress receipt comes before this.

**Resource.** The first Hetzner build reuses the existing lab host
(byotlab-1). It needs no new server. Its cost is that host's existing cost,
and Hestia states it with the go request. A new resource would be a
separate request, with its own cost.

**Executable acceptance sequence.** A step counts as done only on its own
evidence. An image build, or a container that is up, is never reported as a
running agent.
1. The host egress receipt.
2. Athena's ACK on the bundle bytes (Juan's go is given).
3. The image is built and the Compose project is up (`provision.sh
   team-container up`). Evidence: `docker inspect` diffed against
   `compose.yaml`.
4. Build checks 1–3 and the bypass checks (above).
5. Harness auth is restored under the setup-token pattern:
   - oats#1787 (O4, `fromFile`) and oats#1786 part 2 (O5,
     `oats harness token set`) are merged and released;
   - the person runs `oats harness token set claude --server <id>` on their
     own machine;
   - the receiver's `status` shows the fingerprint, and the host file is
     `root:<agent group>` 0440.
6. `oats server connect` reports ready. Agents A and B, two admitted seats in
   the one team container, are spawned from their
   seats (preview, then apply) with `CLAUDE_CODE_OAUTH_TOKEN: { fromFile:
   /etc/agent-login/claude-token }`.
7. `claude -p` succeeds for each of A and B, and A and B exchange aweb mail. claude.ai and mcp-proxy are
   refused, with forwarder evidence. No `.credentials.json` exists.
8. The secrets broker proof (allowed and refused) and the external audit
   read (section 9).
9. The full section 12 receipt.

Until step 7 passes, the milestone is reported as "not running".

**Build checks 1–7 run first** (Hestia 898b84cf, 3985f438):
1. the host reaches the internal network's containers (ProxyJump);
2. Docker's embedded DNS behaviour on an internal network;
3. a host gateway IP on the `agents` bridge;
4. the variable Claude reads a setup-token from: `CLAUDE_CODE_OAUTH_TOKEN` (documented);
5. that a setup-token is never refreshed by the client;
6. where setup-tokens are revoked: settled by Juan (section 7).
7. the authority a setup-token carries: answered, inference-only (section 7).

**Bypass checks**, run from the agent container. Each needs evidence; an
exit code alone is not a PASS.
- direct IPv4 to a public host and to an allowlisted host's real IP:
  ENETUNREACH, with the route table printed;
- IPv6: no address, connect fails;
- `1.1.1.1:53` over udp and tcp: ENETUNREACH;
- an unlisted name: NXDOMAIN, with the resolver's log line;
- the lab3 container IPs, `172.17.0.1:5433`, the host gateway on
  :22/:80/:443/:8443, and `169.254.169.254`: ENETUNREACH, or the input-chain
  counter moves;
- `--resolve` of an unlisted name to the forwarder: refused, logged, no
  upstream;
- `--resolve github.com` to the forwarder: lands on GitHub;
- other ports on the forwarder: refused;
- forwarder deny4 rebinding: refused by its egress chain, and the counter
  moves;
- positive control: an allowlisted name works, with a forwarder log line and
  the egress counter moving.

## 5. Managed Kubernetes runtime

This section states the limits the chart must fit on an organisation's own
managed Kubernetes cluster that deploys through GitOps, and what it assumes of
such a cluster. The cluster's own inputs come from its operator and are not
recorded here. No cluster is bought or set up for this review.

- **Placement and deploy route.** The cluster operator decides the namespace
  model, quota and deploy route. The agent part of the Helm chart (O1) is a
  chart for the operator's pipeline to consume, not one we apply. Each team
  runs one StatefulSet with a PVC mounted at `/state`, on the cluster's
  default ReadWriteOnce block storage (no class named), so replicas stay at 1.
- **Admission limits.** Admission policy may warn today and deny later, so the
  chart fits these limits from the start:
  - requests at most 500m CPU and 2Gi memory; limits at most 2 CPU and 4Gi;
  - liveness and readiness probes: a tcpSocket probe on the sshd port, the
    same check as the Compose healthcheck;
  - an ephemeral-storage limit;
  - a PodDisruptionBudget that does not block node drains with one replica
    (`maxUnavailable: 1`);
  - a replica count within 1-5 (here 1);
  - `terminationGracePeriodSeconds: 45`, matching Compose's
    `stop_grace_period`, so `oats host run` stops the agents in order on a
    drain.
- **Pod security is set by the chart itself; admission is not relied on.**
  The chart sets `runAsNonRoot`, `allowPrivilegeEscalation: false`,
  `capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true` and
  `seccompProfile: RuntimeDefault`. The kubectl acceptance script asserts
  each of them on the running pod.
  - The read-only root filesystem needs writable `emptyDir` mounts (for
    example `/tmp` and the agent's home) beside `/state`.
  - `stdin` and `tty` stay off in the pod spec.
- **Service account.** `automountServiceAccountToken: false`, and a dedicated
  ServiceAccount with no RBAC and no cloud IAM binding. It is fixed at the
  first deploy and not changed afterwards.
- **Network.** NetworkPolicy enforcement is not assumed, so egress control is
  our forwarder (section 4.1's pattern): a forwarder pod plus a resolver, with
  an egress NetworkPolicy that allows only the forwarder where the cluster
  enforces it.
  - Hostname-allowlisted egress is not claimed on a cluster until its
    operator confirms NetworkPolicy enforcement.
  - The pod's DNS egress goes only to the forwarder's resolver, never to
    cluster DNS. Otherwise the DNS-tunnel residual that section 4.1 closes
    comes back.
- **Operator access, D2: (i), decided by both OATS sides.** There is no TCP
  ingress to the pod, so operators port-forward. The route assumes sshd may
  run in the pod.
  - sshd runs in the pod, and the operator's ssh config uses a ProxyCommand
    over `kubectl port-forward`. There is no kernel change.
  - Under drop ALL and non-root, sshd logs in only as its own user, on a port
    above 1024.
  - The operator needs port-forward rights scoped to the one namespace; no
    exec right is needed.
  - If the cluster forbids sshd in pods or port-forward, a `kubectl exec`
    target (ii) comes back to both sides as a contract question.
- **Image.** The image is pulled from the registry the cluster operator
  designates, with its pull secret.
- **Origin.** The agents use the deployment's configured canonical aweb origin
  and its audience; which origin is a deployment input.

## 6. Agent identity and team authority

### 6.1 O2: can spawn attach an operator-admitted local identity without team custody? (source check)

**Yes. A supported path exists, with two limits.**

Source: oats-aweb 2c2251a, `oats-package/capabilities/oats-aweb/bin/oats-aweb.mjs`.

- **Default local spawn (line ~1842)** mints the identity with
  `aw init --join-from <root> --join-team <team>`. That creates an invite with
  the root's team authority, so for BYOT it needs the team key.
- **`settings.oats.aweb.identity.source` (line 1816, `retainedSeatSpawn` at
  line 1033)**:
  - takes the absolute path of an existing `.aw` (signing key plus team
    certificate);
  - takes a seat lock, refusing a seat whose holder's home still exists;
  - copies the identity into the instance home and runs
    `aw workspace connect`;
  - rolls back on failure.
  - It mints nothing, and it needs neither the team key nor the controller
    key.

**Per-spawn selection: checked (OATS CLI 0.69.9, read-only preview).**
- `oats spawn <soul> --preview --json --provider oats.aweb identity.source=<abs path>`
  puts the path into `decision.effective.providers.oats.aweb.identity.source`,
  with origin `spawn` / `--provider oats.aweb`.
- OATS documents this exact use as its example of a per-spawn provider
  setting (docs/workspaces.md, "Provider payloads have three homes").
- A preview runs no provider hook. So "attaches without minting" rests on the
  source reading above: `retainedSeatSpawn` ends in `out()` or `fatal()` and
  never reaches the `aw init --join-from` mint. The first live apply is the
  executed proof.
- The preview does not reject a missing seat. At apply,
  `retainedSeatSpawn` refuses it ("holds no signing.key") before taking the
  lock or copying anything.

**Remaining limit.** oats.aweb describes `identity.source` as retaining a
legacy identity, and its messages say so. It needs documenting as the
operator-admitted seat route: an OATS docs and test change that does not block
the build.

**First-slice route.**
1. The operator admits agents A and B outside the container. Each uses a
   fresh local key (acwd.12, `aw id team request --create-local-key`, on aweb
   main, unreleased; or an invite accepted by a human at an interactive exec).
2. The operator places each `.aw` at `/state/seats/<alias>/.aw`.
3. Each spawn names its seat.

The team key and the controller key stay outside the container.

**Disposition of the gap (O2).** The per-spawn check passed. The first
slice uses `identity.source` as it is. oats.aweb documents it as the
"operator-admitted seat" route (O2, OATS). D3 goes to Juan only if this route
is rejected.

**One rule: no team's controller, owner or service authority enters a
container.** Ordinary member keys may enter it.
- **Seat route (first proof).** Agents are ordinary members of H, the team
  that owns the Secrets and Logs installations. Their member keys are in the
  container. H's controller key, team key, owner signing and passkey
  authority, and service keys stay outside. Acceptance tests that boundary
  (section 12, Governance).
- **D3 (team key inside, only if the seat route is rejected).** The workers
  can reach their team's controller authority, so that team T must own no
  Secrets, Logs or other app installation whose owner acts gate other
  people's resources (Athena 963b7138, R1(b)). Protected resources then live
  in a separate, independently governed team H, which is acwd.13's third team
  H. The agents would need their own supported H membership as well. No
  cross-team grant is implied.

### 6.1a What the team key gives (D3 fallback only; Athena R1)

For a BYOT team, the team key is the team's controller authority
(owner-act.md "Who signs"; secrets.md T11). If it were inside the container,
any agent there could:
- certify any key as a member, and revoke any member, humans included;
- publish or replace the team's AWID team-server record
  (`aw id team set-server`), pointing every member at another coordination
  server;
- sign owner acts for every app installed on that team. That includes
  human-role.designate and human-credential.replace, which bind a passkey the
  agent controls, and the first-owner designation that is Secrets' root of
  trust.

So D3 can be accepted only together with the D3 rule above. Its acceptance
check lists team T's app installations and fails if a protected app is
installed there.

**Recovery if the container is compromised.** The holder of the namespace
controller key, which is outside (the operator; for the lab, Juan):
1. rotates the team key;
2. re-certifies the members;
3. re-publishes the team-server record.

The rotation route and how long it takes are to be confirmed with aweb, not
assumed.

### 6.2 What seats separate (Athena 93a0dbe4)

Every seat key under `/state/seats` is readable by every agent in the
container, because they share one uid.

- Seats separate identities for attribution. They do not separate them
  against compromise: one compromised agent can act as any seat in its
  container.
- The receipt states this.
- Grants for the Secrets proof are in section 9: only A_H is granted, so B_H
  is a real negative.

## 7. Native harness authentication (SETTLED: Juan, 2026-11-10)

**Decision.** Juan said it directly to the aweb coordinator, in its own
session (aweb 966245ab, b2ee2cb5): "yes of course, each container will need a
login setting. but it can inherit the login from the spawning container."

- Each team container has a harness login. The container's agents can read
  it. That is the accepted, disclosed exception.
- A container spawned within the same trust group inherits the login. There
  is no new human login per child.
- A container never inherits a login across trust groups or customers.

**Whose account: Juan's own (decided, aweb e778d8e8, 2026-11-10).** Juan:
"we cannot have another claude account for the team." So the containers
inherit Juan's own Claude login. This is an explicit, recorded decision, not
a silent reuse.

**The general pattern (Juan, product direction, aweb e93456c5).** An
employee's agents run on that employee's own Claude subscription. That is
normal, not an exception. It is made safe by the rule below:
- The person runs the `claude setup-token` browser flow themselves. The
  operator provisions only the resulting token.
- The token goes on the team's read-only mount.
- `~/.claude` and a `/login` credential are never copied.
- The agents' usage counts against that person's plan.
- Mixed laptop and server teams keep working as they do today.

**What that login reaches.** Juan's Claude account carries claude.ai
connectors: Gmail, Drive, Calendar, aweb and Claude Docs (seen in T21). A
Claude Code session on that login exposes them as tools; this OATS session,
on the same account, lists them.

- **Inside the container.** `claude.ai` and `mcp-proxy.anthropic.com` stay
  off the allowlist. T21 showed every attempt refused. Every container
  acceptance re-checks that refusal (section 12).
- **Outside the container.** The allowlist does not protect a copied token.
  Any agent can read the token and copy it out through an allowed host (a git
  push, an aweb message). Whoever then holds it has whatever that login
  reaches, from anywhere.
  - **Check 7, answered from Anthropic's documentation** (Hestia e2e61ac7,
    read 2026-11-10; code.claude.com/docs/en/authentication, "Generate a
    long-lived token"):
    > "generate a one-year OAuth token with claude setup-token ... It does
    > not save the token anywhere ... set it as the CLAUDE_CODE_OAUTH_TOKEN
    > environment variable ... It can only make model requests, so it can't
    > establish Remote Control sessions or fetch claude.ai connectors."

    So a setup-token is inference-only, and disabling the connectors stays
    optional hardening.
  - **By contrast, the `/login` credential** (`~/.claude/.credentials.json`)
    carries `user:inference`, `user:mcp_servers`, `user:sessions:claude_code`,
    `user:file_upload`, `user:plugins` and `user:profile`. This was read from
    the lab's credential metadata, with no values read. That credential is
    connector-capable.
  - **Rule:** containers get only a setup-token. A copy of a `/login`
    credential never enters a container. Acceptance checks the mount holds a
    setup-token and that no `.credentials.json` exists in the container.
- **Revocation (check 6, settled by Juan, aweb 1528ec35, 2026-11-10).**
  Revoke by signing the session out in claude.ai settings. Juan: "revocation
  is solved, i am telling you. it is officially supported by anthropic." Then
  remove the host file. It is the only containment if the token leaks.
- **Usage.** Agent usage counts against that person's plan limits (for the
  lab, Juan's) and shows in their account's usage. A copied token still
  permits inference. Every container that mounts the token is inside one
  compromise boundary.

**Disclosure** (Athena 963b7138, note 1; Hestia 3985f438, A5).
- One login per trust group means one compromise exposes every container of
  that group, and one revocation cuts them all.
- Every container that shares the token has that token's authority: model
  requests on that person's subscription, within its plan's usage limits. It
  cannot reach claude.ai connectors or Remote Control. Locally configured MCP
  still works, and separately configured tools or credentials are not limited
  by this.
- Runtime limits, mounts, egress and requested reductions do not narrow the
  credential.
- Narrower provider authority needs a distinct credential, for example an
  Anthropic API key in a team workspace with a console spend limit. That is a
  choice of credential, not something the recipe can impose.
- Spend limits are whatever the provider offers.

**Constraint on any inheritance mechanism.** The credential moves operator
to container only. It never passes through an agent-writable path, mail or a
soul.

**Claude Code** (the only harness enabled in the first slice; Hestia
3985f438, A1–A4). The CLI offers `setup-token` ("Set up a long-lived
authentication token (requires Claude subscription)"); read on 2.1.319 and
2.1.321.

- **Bootstrap.**
  - The person (for the lab, Juan) runs `claude setup-token` in their own
    browser flow. The operator provisions only the resulting token.
  - The token goes into `/srv/oats-team/<team>/login/claude-token` on the
    host, `root:20001`, mode 0440.
  - It is mounted read-only at `/etc/agent-login/claude-token` (section 4.2).
  - The value never appears in the image, Compose or Helm literals, an env
    file, `oats-local.yaml`, mail, or any recorded command or receipt.
  - Being read-only does not hide it from the agents.
- **Delivery to the harness: gap O4.**
  - The token must reach Claude as the variable Claude reads (check 4).
  - OATS launch env takes literals or `{ fromEnv: NAME }` resolved in the
    starting process. The routed spawn runs over non-interactive ssh, which
    reads no login profile, so no supported OATS route exists today for a
    mounted file to become a launch variable.
  - O4 provides one (oats#1787): `CLAUDE_CODE_OAUTH_TOKEN: { fromFile:
    /etc/agent-login/claude-token }`.
  - **Persisted versus process-only.** The value is persisted only in the
    root-owned read-only host file and its mount. It is never written into
    an OATS config, `oats-local.yaml`, `instance.json`, the start-env record
    (which keeps a keyed digest only), tmux argv or a log. At each session
    start OATS reads the file and passes the value through a 0600 per-start
    handoff that the launcher deletes before it executes the harness. So the
    value exists as `CLAUDE_CODE_OAUTH_TOKEN` only in the harness process's
    environment, which Claude requires.
- **Inheritance.** The provisioner mounts the same read-only file into every
  container of that team and refuses it for any other team. No copies.
  - HYPOTHESIS (check 5): a setup-token is never refreshed by the client, so
    no rotation race arises.
  - If check 5 fails, the mechanism is re-specified before any claim about
    multiple containers.
- **Refresh.** None for a setup-token (check 5).
- **Revocation.** Revoke at the provider (check 6: where setup-tokens are
  listed and revoked), then remove the host file. Running harness processes
  keep the value until restart, so the sequence is:
  1. provider revoke;
  2. file removal;
  3. session restart, or container down.

  The receipt shows an auth failure afterwards.
- **Proof.** An inherited mount is not evidence of authentication.
  Acceptance runs `claude -p` in every container that claims the login.

**Other harnesses.** Each gets the same treatment before it is enabled: its
own supported long-lived or refreshable credential, on one read-only team
mount, with its own checks. None is enabled in the first slice.

**GitHub** (coordinator's accepted direction).
- A GitHub App with short-lived installation tokens scoped to the team's
  repos.
- The App's private key and the minting service sit outside the agent
  boundary.
- Tokens handed to native git and gh **are present in the container** and
  readable by its agents for their lifetime (about an hour).
- Delivery and the refresh hook (a git credential helper calling the minter)
  are open with Secrets and aweb: gap G1.
- The allowlist adds api.github.com only when token use is real, as a
  reviewed delta.
- The first slice needs no GitHub credential: public pins only, and no
  pushes.

## 8. Credential classes (summary)

| Class | Where | Readable by agents |
|---|---|---|
| each agent's own identity key | its seat and home | yes (its own; the container shares one uid) |
| harness login (Claude): Juan's account, by decision | read-only team mount (section 7) | yes; the accepted exception, with the section 7 connector condition |
| GitHub installation token | delivered for native tools | yes, for its lifetime |
| BYOT team key, namespace controller key | outside the container | no |
| controller and owner keys and passkeys of team H (protected resources) | outside, human custody | no |
| GitHub App private key and the token minter, cloud provisioning tokens | outside | no |
| Secrets KMS and store keys, broker and Logs databases | outside, operator custody | no |
| protected customer API credentials | Secrets broker only | no; never returned or mounted |
| host HOME, Docker socket, Kubernetes SA token | not present | no |

## 9. Secrets: credential boundary and first broker proof (aweb-expert-secrets-root, ed6adffc)

This section is the Secrets root's source-checked contribution, edited for
reading. Its source basis is listed at the end.

The build is authorized for the bounded Hetzner slice only (see Status).
Acceptance must be repeated on Hetzner Compose and on managed Kubernetes. Neither
the existing host-UID lab nor a pass on the other target qualifies it.

**Fit with section 6.1.** Agents A_H and B_H are the operator-admitted seats
of section 6.1, admitted to H by H's controller outside the container. For the
first proof, H is their team, and no team key of any team enters the
container.

### Authority and custody

**Two teams.**
- **Team T** is the worker-owned OATS team. That includes any controller
  deliberately placed inside the trust group under D3.
- **Team H** is the protected resource team. It owns the Secrets and Logs
  installations. All of these stay outside agent reach:
  - H's controller;
  - human owner signing and passkey authority;
  - service keys;
  - custody and KMS authority;
  - databases and configuration.

**Agents in H.**
- A_H and B_H are explicitly admitted ordinary members of H.
- OATS must not receive H's controller to mint their identities.
- There is no cross-team secret grant: both requests authenticate as members
  of H, the team that owns the installation.
- Inheritance (acwd.13/.16) is not needed for this first explicit admission.

**Shared trust group.**
- An agent's own ordinary member key may be inside its assigned trust group.
- Where A and B can reach each other's signing keys, their effective
  authority is shared. The proof checks the policy of the presented principal
  and the protection of the external customer token. It does not check that
  A is contained from B.
- Per-agent containment needs a separately demonstrated execution and key
  boundary. Sharing within an approved trust group remains permitted.

**The protected customer credential.**
- It is ingested only through the genuine owner console.
- The external broker opens it briefly and injects it into its fixed upstream
  request.
- The agent gets a projection with no credential in it: not a file, an
  environment value, a minted bearer token or a credential-shaped response.

**Limits of custody.**
- A local custody key plus ciphertext bypasses app policy.
- Reachable KMS credentials carry their decrypt authority.
- KMS does not isolate agents from a compromised service.
- Service and host administrators remain trusted.

**Native harness login.** It is disclosed separately, under D1 (section 7).
An agent-readable native login is not protected by the broker just because
the harness runs in a container.

### Required sequence and current stopping points

1. **Pin the selected source and cohort, and the actual service placement.**
   - Secrets and Logs must be outside agent execution, mounts and management
     interfaces.
   - They need real TLS API and console origins, and recorded custody of
     keys, DB and config.
   - Lab3's 1ed1abd9 receipt establishes a bounded install and health only.
     It does not establish signed-member, owner, hook-delivery, reader or
     container-profile acceptance.
   - Repeat the placement and denial evidence on each target.

2. **Explicitly admit two real H members.**
   - Use the existing admission: worker-local signing-key preparation, then
     controller request, add-member and fetch-cert. H's controller stays on
     the operator side.
   - Record each canonical principal, certificate ID and team. No fixture
     certificate or authority row.
   - Each caller sends the real team-auth v2 request:
     - headers: DIDKey Authorization, X-AWEB-Timestamp,
       X-AWID-Team-Certificate and X-AWEB-Signed-Payload;
     - bound to the method, the external API origin, the raw target and
       query, and the exact body hash.
   - Preserve Host and verified TLS, and meet the clock-skew and currentness
     checks.
   - A certificate containing did:aw must match its current registry key. A
     local certificate uses its did:key principal.
   - **Certificate status lookup.** The runtime already supports public
     status lookup for a presented certificate, including in private teams:
     `/v1/namespaces/{domain}/teams/{name}/certificates/{certificate_id}/status`.
     - AWIDTeamCache uses this path when its service token is unset, and
       verifies the presented certificate against the current team key.
     - It exists at the source baseline and in the e3a1d9f76 registry cohort.
     - Do not invent a registry-wide service credential. Verify that the
       selected configuration actually uses an accepted currentness path.
   - Publication, revocation and signed team-server discovery must succeed
     against the actual registry.

3. **Establish the real installation grant, separately from secret grants.**
   - Both H-member requests must pass the fresh installed-app grant, the
     team, installation and generation fences, and the `secrets:use` scope.
   - Add `secrets:read` only for actual list, describe or status use.
   - This common tool-level authority is not permission to use a particular
     secret.
   - A missing certificate, scope or installation is an earlier refusal, not
     the principal-grant negative below.

4. **Complete the supported first-owner bootstrap before any configuration.**
   - A genuine human-role designation, current human/member evidence, passkey
     enrolment and LOGIN must compose through the supported H/N path.
   - The critical work that remains:
     - the shared 4.2 follow-up and factory, and the B2 hooks;
     - Secrets 16.43a holding and backfill, and Logs 16.44 holding and read;
     - the console 4.4 and app 4.5 adapters;
     - shared 16.41 delivery and the app's 16.43b writer.
   - Owners, in their existing slices: secrets-shared, secrets-app,
     secrets-console, logs and logs-reads.
   - Component APIs, legacy helper bootstrap, seeded authority and health are
     not completion receipts.
   - Stop until those owners hand back the composed path.

5. **Owner-confirm the synthetic configuration.**
   - A human enters the value, which creates a synthetic secret.
   - For the smallest proof, choose a brokered HTTP named operation:
     - fixed destination, method and path;
     - typed, bounded parameters;
     - fixed credential injection;
     - an explicit safe projection.
   - Owner-confirm grant/1 with:
     - subject `{principal: <A_H's exact canonical DID>}`;
     - capability `use`;
     - the operation's ID and digest;
     - the matching `policy_digest`.
   - B_H must have no direct or role-derived grant matching that secret and
     operation. If both members are granted another use, keep the chosen
     negative explicitly outside B's coverage.
   - Per-use approval is a separate policy condition. `approve_only` requires
     an eligible enrolled approver and a fresh APPROVE of the frozen request;
     LOGIN cannot satisfy it. No approver is invented for a policy that does
     not require approval.

6. **Activate audit delivery and prove read access.**
   - Register and activate the real post-secret-use-hook binding from Secrets
     to Logs. It needs the actual producer and target installation and
     generation, signatures, CA and egress settings.
   - Configure the genuine reader through 16.44/4.4, with its real session.
   - Require the full chain: persisted outbox → Logs ingest and ledger →
     signed receipt → an authorized console JSON read. Bounded health is not
     enough.
   - Logs outside the agent trust group is independent of the agents, but not
     automatically of the shared administrator. State external witness
     coverage and governance before claiming tamper-evidence against that
     administrator.

7. **Constrain networking on both platforms.**
   - Permit the declared AWID/coordination, Secrets API and selected harness
     endpoints needed for actual work and messaging.
   - The synthetic customer upstream is a broker-only destination, never on
     the agent allowlist.
   - Console and owner access go through the supported operator route.
   - Reaching a service API does not give access to service keys, databases,
     container sockets or Kubernetes management authority. Prove those
     denials rather than relying on a namespace or UID label.

### First proof and required evidence

- **A_H, allowed.**
  - A_H submits the named operation through the actual installed manifest
    tool request (`POST /v1/secrets/{secret}/requests` with request_id,
    operation and params).
  - Require a completed structured outcome and the one authenticated
    synthetic upstream effect.
  - The response carries exactly the safe projection. No token is returned or
    mounted.
  - HTTP 200, or "admitted", alone is not completion.
- **B_H, refused.**
  - B_H submits a correctly signed comparable request, after passing the same
    team, installation and tool-scope controls.
  - Require `grant_missing` (or an explicitly chosen `operation_not_allowed`
    case) before the custody opens and before any upstream effect.
  - Record that B actually reached the secret-grant decision. A signature or
    scope refusal is a separate test.
- **Direct upstream attempt.**
  - The runtime network profile denies an agent's direct upstream attempt.
  - Its evidence is the network or forwarder refusal and the absence of an
    upstream effect. Never a fabricated broker event for a request the broker
    never saw.
- **Logs.**
  - Verify A's and B's actual signed events through Logs. Use server
    mediation, not a client-origin event, as evidence of the broker effect.
  - Correlation:
    - A uses its returned request_ref, and the dispatch ID where one was
      allocated.
    - An admission refusal allocates no dispatch, so B uses its returned
      use_ref plus the signed trace_id/event_id.
    - Do not expect the raw caller request_id to be a public hook field.
  - No new request ID and no blind redispatch may mask an unknown outcome.
- **Protected objects.** Record attempted reads of existing protected key and
  state objects, with owner-side existence controls, the actual group, UID and
  policy evidence, and the target's network denial. A scan alone does not
  prove that a secret was never reachable.

**Later work that does not block this slice.**
- This HTTP slice needs no runner.
- The later fixed TLS CLI job also needs:
  - the native reviewed installation and transport;
  - the exact narrow supervisor policy;
  - genuine registration;
  - receiver, CA and username mapping;
  - the final job and local-pin FIT;
  - lifecycle acceptance.
- No real Hetzner token, financial ceiling or provider lifecycle enforcement
  is implied.

**Source basis** (source review only, no new runtime):
- aweb commit 02f80a15358ff1865302bac3aa900cd493fc862a: grant.py:88-122;
  runtime/team_auth.py:260-264, 393-445 and 693-752;
  runtime/authorization.py:246-290; admission.py:360-380;
  broker_service.py:605-657; broker_audit.py:398-460; tool_results.py:39-45;
  design/secrets.md §4 and §14.1.
- Checkpoint e3a1d9f76 contains the public per-certificate status endpoint.
- The first-owner and reader status comes from the current
  acwd.17/.4.2/16.44 task receipts, not a live run.

## 10. Missing pieces and owners

| Id | Owner | Piece | State |
|---|---|---|---|
| O1 | OATS | Dockerfile, the config contract doc, the agent service in Compose, the agent part of the Helm chart, one acceptance script (docker and kubectl variants) | authorized for Hetzner (docker variant first) |
| O2 | OATS | document `identity.source` as the operator-admitted seat route (docs and tests) | the per-spawn check passed (preview); the docs change is authorized |
| O3 | OATS | managed-toolchain profile: the five npm consumers refuse in a container (oats#1784) | filed |
| O4 | OATS | delivery of a mounted harness token file to the launch env: `{ fromFile: <abs> }` launch env values, out of tmux argv (oats-project/oats#1787) | both sides APPROVE at 5db92600; merges together with O5 |
| O5 | OATS | document the setup-token onboarding step (the person runs `claude setup-token`, and the operator provisions only the token; read-only mount; never copy `~/.claude`) in OATS's server and onboarding docs, together with O4; `oats harness token set` delivers the token from the person's machine to the operator's forced-command receiver (oats-project/oats#1786 part 2) | in review; up to four further sequential reviewers authorized |
| O6 | OATS kernel | refuse (server and container targets) or warn (laptops) when a `/login` credential is present at harness start; the same assertion as the section 12 check (Athena c49ca080) | decided by both sides: refuse with `E_CLAUDE_LOGIN_CREDENTIAL` when OATS sets `CLAUDE_CODE_OAUTH_TOKEN`; otherwise silent (a personal laptop login is supported); in #1787 |
| G1 | Secrets + aweb | GitHub App installation-token minting service and the git credential helper | open; not on the first slice |
| H1 | Hestia | Compose bundle, forwarder, resolver, nft chains, provision.sh actions, build checks 1–6, bypass checks | design ACKed at 8b86e9ca with notes now folded in; build after the host egress receipt and the go |
| L1 | the Kubernetes target owner | cluster inputs and section 5 | ownership accepted; NetworkPolicy enforcement, sshd in pods, operator port-forward, namespace model and origin to be confirmed |
| S1 | Secrets | first-owner chain (section 9, item 2) | in progress |

## 11. Decisions

**Settled.**
- **Build go (bounded Hetzner slice).** Juan, 2026-11-10 (servers bb6a1b80).
- **D1, harness authentication.** Juan, 2026-11-10 (section 7).
- **GitHub App direction.** The coordinator's accepted direction (section 7).

**Open.**
- **D2, Kubernetes operator access.** (i) chosen by Pepe's side and OATS, conditional on sshd being allowed in pods (section 5).
- **D3, team key inside the container.** It goes to Juan only if the O2
  route is rejected; the evidence is in section 6.1.

## 12. Acceptance (each platform on its own evidence)

Evidence comes from `docker inspect` diffed against `compose.yaml` on Hetzner,
and from the admitted pod's YAML plus the NetworkPolicy on Kubernetes.

**Isolation**
- The declared uid.
- All capabilities dropped; no privilege escalation; read-only root
  filesystem, as set by the pod spec (Kubernetes: asserted on the running pod).
- Mounts exactly match the approved list: `/state`, optional `/work`, the
  read-only `authorized_keys`, the read-only `/etc/agent-login/` and the
  read-only `/etc/resolv.conf`.
- No `docker.sock`, no host HOME, not privileged, no service-account token.
- Non-root sshd starts.
- uid 20001 cannot read anything owned by 10001 (Hetzner).
- The team key and the controller key are absent from the container.

**Network**
- An allowlisted name resolves to the forwarder and works for Claude, git
  (https), gh and aw.
- An unlisted name returns NXDOMAIN.
- A forced resolve of an unlisted name to the forwarder is refused there,
  with a log line and no upstream connection.
- These are unreachable: a direct IP (including an allowlisted host's real
  IP), IPv6, `1.1.1.1:53`, `169.254.169.254`, the lab3 service IPs and
  `172.17.0.1:5433`.
- On Kubernetes, the same checks run through the cluster's egress path.

**OATS**
- `oats server connect` reports ready.
- Spawn of A and B from their seats: a preview, then the apply.
- `oats status --server` shows the lock commit, and the viewer attaches.
- A package sync works.
- A global npm install fails, as O3 says.

**Harness**
- `claude -p` succeeds for each agent in the team container.
- `claude.ai` and `mcp-proxy.anthropic.com` are refused from inside the
  container, with forwarder evidence (re-checked on every container
  acceptance).
- The mounted credential is a setup-token, and no `.credentials.json` (a
  `/login` credential) exists anywhere in the container.


**Governance**
- Seat route:
  - H's controller key, team key, owner and passkey material, service keys,
    KMS credentials and database credentials are absent from the container;
    a search and attempted reads show it;
  - an agent's attempt to perform an owner act or add a member is refused.
- D3 route: team T's app installations are listed, and the check fails if
  any protected app is installed there (6.1).

**Coordination.** A_H and B_H exchange aweb mail and chat.

**Broker** (after S1). The proof in section 9. A search of the container's
filesystem and environment finds no customer token.

A general shell stays available inside the container.

# agents: the OATS team container

One team trust group in one container: the agents, their wake broker and
`oats host run`. Written by the owner of the team image.

## Inputs

| Key | Becomes | Constraint | Default | Purpose |
| --- | --- | --- | --- | --- |
| `agents.image` | `AGENT_IMAGE`; StatefulSet image | `repository@sha256:<64 lowercase hex>` | none | The same reviewed agent image digest in both wrappers. |
| `agents.uid` | `AGENT_UID`; pod runAsUser | integer1..2147483647; must satisfy signer.workerUids cross-validation | 20001 | Runtime owner of the team state and processes. |
| `agents.gid` | `AGENT_GID`; pod runAsGroup | integer1..2147483647 | 20001 | Runtime primary group; Compose login files must be readable by it. |
| `agents.secrets` | read-only `/etc/agent-login/`; Compose `TEAM_LOGIN_DIR` resolves below compose.secretsDir | dedicated existing Secret/directory reference; only the harness login file | `agents` | D1 login source; its path is the accepted exception to/run/secrets. Never service/provider/tool/DB credentials. |
| `agents.cpus` | `AGENT_CPUS`; resources.limits.cpu | positive CPU-core number, at most2 for the accepted budget | 2 | Same CPU limit in both wrappers. |
| `agents.memory` | `AGENT_MEMORY`; resources.limits.memory | positive integer bytes, at most4294967296 | 4294967296 | Same4Gi memory limit; byte units work without treating Docker and Kubernetes quantity spellings as interchangeable. |
| `agents.tmpSize` | sized `/tmp` tmpfs/emptyDir; Compose `AGENT_TMP_SIZE` (new mapping input) | positive integer bytes | 134217728 | Same128Mi memory-backed temporary space; Compose must apply the size instead of silently ignoring it. |
| `agents.resolverIp` | sole pod nameserver; Compose `RESOLV_CONF_FILE` generated from it | one IPv4 address; required when boundary is enabled | none | Only the egress resolver answers the agent; mount its generated resolv.conf read-only on Compose. |
| `agents.caFile` | Compose `AGENT_CA_FILE`, mounted read-only at `/etc/agent-trust/ca.pem`; Kubernetes: the root wrapper stages it as `generated/agent-ca.pem`, projected read-only (0444) at the same path | absolute path of a public PEM CA, never a private key; optional | none | A deployment whose origins a private authority signed: exactly `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS` point at it before the supervisor starts, so Go aw, the wake broker and Node verify against it alongside the normal roots. No verification is relaxed. |
| `agents.mirrorsDir` | Compose `AGENT_MIRRORS_DIR`, mounted read-only at `/mirrors` outside `/state` | absolute host path; optional; Compose only | none | Operator-maintained bare Git mirrors of the OATS workspace, its members and its packages, refreshed outside the container with a source/ref/refresh manifest; `/state/home/.gitconfig` rewrites the canonical URLs to `file:///mirrors/`. Kubernetes never turns it into a hostPath: with `agents.kubernetes`, mirrors need `agents.kubernetes.mirrorsClaim`. |
| `agents.network.subnet` | Compose agents network IPAM | valid private IPv4 CIDR; contains the agent and egress addresses | `172.30.0.0/24` | Shared declared address plan for the isolated agent side. Kubernetes wrapper validates the chosen CNI/addressing mapping rather than promising static pod IPs. |
| `agents.network.address` | `AGENT_IP` for Compose | usable IPv4 address in agents.network.subnet; distinct from proxy/gateway | none | VM SSH/resolver route; this is not an alternate network or a default-route grant. |

## Secret files

| Name | Owner and mode | Provisioned by |
| --- | --- | --- |
| `claude-token` (D1: `/etc/agent-login/claude-token`) | root:agent-readable-group,0440; containing host directory0750, read-only projection; Kubernetes fsGroup supplies the readable group | Operator through credential/Secret tooling by stdin; inference-only harness login. A source may be empty before provisioning; no placeholder credential. |

## Platform-only inputs

| Key | Platform | Why |
| --- | --- | --- |
| `agents.kubernetes.fsGroup` | Kubernetes | Default20001 positive group; fsGroupChangePolicyOnRootMismatch keeps private SSH host keys0600 across remount. Compose provisioner owns/chgrps host sources instead. |
| `agents.kubernetes.stateSize`, `agents.kubernetes.storageClass` | Kubernetes | PVC default10Gi/RWO; empty class omits storageClassName. Compose uses operator-provisioned state storage and cannot enforce a PVC request or storage class. |
| `agents.kubernetes.requests.cpu`, `agents.kubernetes.requests.memory` | Kubernetes | Defaults0.5cores/2147483648bytes, positive and<=limits; Compose has no equivalent scheduler reservation in the current fragment. |
| `agents.kubernetes.ephemeralStorage.request`, `agents.kubernetes.ephemeralStorage.limit` | Kubernetes | Defaults268435456/1073741824bytes, positive and ordered; the API/runtime accounts ephemeral storage, unlike ordinary Compose. |
| `agents.kubernetes.authorizedKeys.kind`, `agents.kubernetes.authorizedKeys.name` | Kubernetes | Existing ConfigMap(default) or Secret with authorized_keys; only that public-key file projected0444/read-only. Compose binds an existing regular public-key file. |
| `agents.kubernetes.imagePullSecrets`, `agents.kubernetes.imagePullPolicy` | Kubernetes | Existing pull-Secret references and pull policy(defaultIfNotPresent); runtime image-pull mechanisms differ. No credential content in values. |
| `agents.kubernetes.mirrorsClaim` | Kubernetes | An existing operator-provisioned PVC of bare Git mirrors, mounted read-only at `/mirrors` outside `/state`; required when mirrors are configured for Kubernetes (`agents.mirrorsDir` alone is refused there, naming this key); never the agents' state claim. The wrapper creates no mirror store and fetches no sources; PVC existence says nothing about freshness. |
| `agents.kubernetes.service.enabled` | Kubernetes | Defaultfalse; optionalClusterIP only, with SSH via port-forward; VM wrapper connects to its private address. |
| `agents.kubernetes.networkPolicy` and proxy namespace/pod selectors | Kubernetes | Select the egress workload in NetworkPolicy; runtime enforcement must be measured. Compose implements the boundary with its network/proxy. Canonical key spelling follows the egress descriptor; no independent second proxy selector set. |
| `agents.compose.stateDir` | Compose | Existing absolute TEAM_STATE_DIR, runtime-owned0700, create_host_path:false; Kubernetes provisions its PVC instead. |
| `agents.compose.authorizedKeysFile` | Compose | Existing AUTHORIZED_KEYS_FILE, root-owned regular public-key file0644, mounted read-only; Kubernetes names a projection object. |
| `agents.compose.workDir` | Compose | Optional TEAM_WORK_DIR opt-in/work bind; absent by default and added explicitly to approved mounts. Current Kubernetes agent has no/work mount. |
| `agents.compose.pidsLimit` | Compose | Required positive AGENT_PIDS; Kubernetes has no portable per-pod manifest pids-limit field. |
| `agents.compose.name` | Compose | Docker-safe TEAM name suffix, separate from canonical team.id; a canonical team id containing a colon cannot be used as a Docker container name. Kubernetes release/namespace are wrapper connection context. |

Image: pinned container/agent image, same digest across wrappers; no credentials or host keys baked in.
Port:2222, SSH as agent; one replica and one approved team trust group.
Health: TCP2222; supervisor separately requires its own live broker PID with daemon_running:true before SSH/host run;45s stop grace and agents-before-broker stop.
Depends on: enforced egress boundary/resolver before agent launch, persistent/state, read-only login/public-key sources, and operator-provisioned deployment/ordinary-member seats; no direct PostgreSQL, Redis, service-key, docker-socket, hostPID or privileged access.

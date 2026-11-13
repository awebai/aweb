| Schema key | Existing env name or mount | Type/constraint | Default | Purpose |
| --- | --- | --- | --- | --- |
| `egress.image` | `EGRESS_IMAGE`; service image | `repository@sha256:<64 lowercase hex>` | none | One proxy image in Compose and Helm. |
| `agents.resolverIp` | `EGRESS_ADDRESS`; derived policy `frontAddress` | static IPv4 address on the agents network, or proxy Service address in Kubernetes | none | Authoritative DNS replies and TLS entry point. |
| `aweb.publicOrigin` | derived policy `targets.aweb.origin` | exact HTTPS DNS origin on 443 | none | Agent access to aweb. |
| `secrets.publicOrigin` | derived policy `targets.secrets.origin` | exact HTTPS DNS origin on 443 | none | Agent access to the Secrets broker API, without mounting its keys. |
| `logs.publicOrigin` | derived policy `targets.logs.origin` | exact HTTPS DNS origin on 443 | none | Agent access to Logs. |
| `signer.requestOrigin` | derived policy `targets.signer.origin` | exact HTTPS DNS origin on 443; equals validated profile `request_origin` | none | Signed prepare and receipt access, conditional on runtime Host/SNI refusal proof. |
| `signer.humanOrigin` | derived policy `humanOrigin` | exact HTTPS DNS origin; excluded from agent routes | none | Prevent the browser approval surface becoming an agent destination. |
| `team.registryUrl` | derived policy `targets.registry.origin` | exact HTTPS DNS origin on 443; equals validated profile `registry_origin` | none | Sender verification in the broker's Node channel-core child and Go aw. |
| `team.registryRoute` | ingress probe route input `registry` (`egress_policy.ingress_routes`) | `local` or `external` | `external` | `local`: a `registry` service of this deployment, reached only at one of `egress.privateIngressAddresses`, probed through its ingress with its log as witness. `external`: the registry's operator's; refused if `registry` is a service or one of the deployment's own addresses serves it, and probed with a positive control only, with no refusal or non-delivery claimed for it. Every other route is local. |
| `signer.profileFile` | wrapper reads public `namespace_authorities` and `registry_origin` | validated existing ProtectedServiceProfile; agents require signer | none | Derive only its provisioned `_awid` TXT records using the existing AWID encoder/parser; no second namespace/controller input. |
| `egress.privateIngressAddresses` | derived policy `privateIngressAddresses` | explicit approved IPv4 ingress addresses; no CIDR or wildcard | empty | Permit private TLS ingress only where declared. Reserved/metadata/loopback and protected-backend denials still take precedence. |
| `egress.external.source` | derived policy `externalTargets.source = {origin: "https://github.com"}` | boolean; the origin is fixed | false | Git fetches of the OATS workspace and its sources. |
| `egress.external.model` | derived policy `externalTargets.model = {origin: "https://api.anthropic.com"}` | boolean; the origin is fixed | false | The harness's model requests. |
| `egress.external.resolvers` | derived policy `externalResolverAddresses` | 1–4 distinct public IPv4 addresses, operator's order, UDP/TCP 53; required with either role, refused without one; never one of the deployment's own, ingress or denied addresses | empty | The DNS resolvers egress alone asks for the external origins' addresses. Each answer is checked against reserved, private, denied and deployment addresses, and the connection goes to the checked address with no second lookup. The agents' DNS still answers only declared names. |
| derived upstream inventory | policy `targets.<role>.addresses` | 1–8 pinned IPv4 addresses per role, resolved/checked before launch | none | No runtime DNS rebinding or general outbound proxy. |
| derived protected inventory | policy `deniedAddresses` | exact protected backend IPv4 addresses, including PostgreSQL and Redis | none | Protected destinations override private ingress exceptions. |
| derived policy artifact | `EGRESS_POLICY_FILE`; `/etc/egress/policy.json`, read-only | complete non-secret artifact specified in README; at most 64 KiB | none | Same generated policy interface for both wrappers, not another operator file/schema. |

| Secret file under `/run/secrets/egress/` | Owner/mode | Who provisions it |
| --- | --- | --- |
| none | No secret mount or serving TLS key. | TLS terminates at the operator ingress. Profile authorities and CA certificates are public trust material. |

| Key | Platform | Why no shared form |
| --- | --- | --- |
| `agents.network.subnet`, `agents.network.address` | Compose | Docker bridge CIDR/static endpoint; Kubernetes uses its pod network and proxy Service. Only proxy joins agents and services; agents network is internal with Docker >=28 isolated gateway mode, not a host-addressed bridge. |
| `egress.kubernetes` selectors/Service address | Kubernetes | NetworkPolicy selects agent/proxy pods and pinned ingress addresses; requires measured CNI enforcement. Compose uses explicit bridge membership. |
| policy artifact bind source | Compose | Wrapper-generated host path, canonicalized on the Docker engine host. Kubernetes mounts the same bytes from a ConfigMap. |

Image: `container/agent/egress/Dockerfile`, one built digest; fixed uid/gid 10001:10001, no credential or operator allowlist baked in.
Port: UDP/TCP 53 and TCP 443, component DNS/service name `egress`.
Health: `node /opt/egress/health.mjs`; exact approved DNS answer, unknown-name NXDOMAIN and live TLS listener; readiness only, not boundary proof.
External roles: egress forwards them by exact SNI to a checked public address. It cannot see or filter the HTTP host, path, method or repository inside the TLS stream, and no external service gives us its logs: the evidence is SNI and public-destination enforcement with DNS/TLS mutants and real `git` and `claude` clients, not non-delivery at the external backend.
Depends on: validated shared deployment config and signer profile; pinned ingress inventory; an enforcing network boundary and TLS ingress rejecting SNI/Host/:authority disagreement before routing; no PostgreSQL, Redis or custody mount.

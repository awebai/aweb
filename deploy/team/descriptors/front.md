# front: the deployment's TLS front

Terminates TLS for every public origin of the deployment with the operator's
certificate and key, and routes each Host to its service. It refuses a request
whose Host its TLS SNI does not name (`strict_sni_host`), and each site refuses
any authority but its own host on port 443 with 421, so the signer's request
host never reaches its human host. Use it on a machine with no reverse proxy
of its own; an operator who already terminates TLS leaves the section out and
routes to the services' published ports.

## Inputs

| Key | Becomes | Constraint | Default | Purpose |
| --- | --- | --- | --- | --- |
| `front.image` | the service's image | `repository@sha256:<64 hex>` of a Caddy 2 image | none | The proxy. |
| `front.secrets` | mount at `/run/secrets/front` | reference | `front` | Where the certificate and key come from. |
| `front.compose.bindAddress`, `front.compose.port` | the published address | | `0.0.0.0`, `443` | Where the public reaches the front. |

The sites are not inputs: one per origin the deployment has (`aweb.publicOrigin`,
`secrets.publicOrigin` and `consoleOrigin`, `logs.publicOrigin` and
`consoleOrigin`, `signer.requestOrigin` and `humanOrigin`), each on port 443,
to the service's fixed port. `teamctl` renders the configuration into
`RUN_DIR/front/Caddyfile` (`render_env.py --front deployment.yaml`) and mounts
it read-only.

## Secret files

| Name | Owner and mode | Provisioned by |
| --- | --- | --- |
| `certificate.pem` | readable by the front (root), `0444` | The operator: the certificate chain, leaf first, naming every site's host (wildcards cover one label). |
| `key.pem` | root, `0400` | The operator: the leaf's private key, unencrypted PEM. |

## Lifecycle

`teamctl start` checks the pair before anything starts: the key is the
certificate's, the certificate is valid now and names every site's host, and
Caddy accepts the configuration and loads them. Any failure stops the start.

To renew, replace both files, then `teamctl reload-tls`: it runs the same check,
reloads the front without a restart, and confirms that every host now serves
the certificate in `certificate.pem`. The front does not obtain or renew
certificates itself (`auto_https off`); renewal is the operator's, before
expiry, and the check refuses an expired certificate at the next start or
reload.

Image: a Caddy 2 image pinned by digest. Port: 443. Health: none of its own;
`teamctl start` waits for the services behind it. Depends on: the services it
routes to.

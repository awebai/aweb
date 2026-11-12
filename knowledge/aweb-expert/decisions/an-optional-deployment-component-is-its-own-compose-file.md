---
type: Decision
title: An optional deployment component is its own Compose file
description: Docker Compose interpolates every service in every loaded file, and the files those services extend, whatever their profile; so an optional component lives in its own Compose file and the rendered COMPOSE_FILE names only the components a deployment has. Profiles alone and `:-` defaults were rejected.
tags: [decision, deployment, compose, discovery]
timestamp: 2026-11-12
---

Recorded by the aweb-expert seat building the team deployment on 2026-11-12,
on a held VM with Docker Compose v5.7.0.

# Discovery

Compose interpolates every service of every file it loads, and every file
those services `extends`, whether or not the service's profile is active. A
`${X:?}` in a profiled service, or anywhere in a body it extends, therefore
makes X required for every deployment, including ones that leave that
component out. The failure appears only when Compose loads the files
(`compose config`, `up`), before anything starts:
`required variable SECRETS_IMAGE is missing a value`, with the `secrets`
profile switched off. A minimal reproduction showed the same through
`extends`. On the same Compose, `extends.file` accepts a variable, and the
extended file's unused top-level `networks` entries are interpolated too.

# Decision

Each optional component of a deployment is its own Compose file
(`deploy/team/compose.<component>.yaml`), with no profile. The rendered env's
`COMPOSE_FILE` names the core file and only the components the deployment
has. Compose reads `COMPOSE_FILE` from the env file when it runs from the
files' directory; a caller that passes explicit `-f` files builds the same
list from the renderer. Profiles stay only for what really is the same
component with a bundled alternative (the bundled PostgreSQL).

# Rejected

- **Profiles alone.** This is the observed failure: a disabled profile does
  not stop interpolation.
- **`:-` defaults in the top-level file.** They do not reach the extended
  bodies, which belong to the components' owning teams and use `:?` by
  design. They would also hide a missing value for a component that *is*
  enabled.

# How to apply

Any work that adds an optional service to a Compose-based deployment (the
team deployment, a Helm or bundle equivalent built from these files) adds a
component file and a renderer entry, never only a profile. The guard is a
test that the core file references none of a component's settings and that
no component file carries `profiles`; render and load every component
combination, including none, before calling the layout done.

Status 2026-11-12: the layout is committed on the deployment branch
(324ee1aaf) and every later VM run used it; it is not on main at 71e608a1c.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-12;
notes/compose-profiles-do-not-make-a-service-optional.md.

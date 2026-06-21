# Memory

One fact per file, indexed here. See the `self-maintenance` skill.

- [lead-drive-to-completion](lead-drive-to-completion.md) — take charge; drive work to done; decide coordination yourself, escalate only genuine product/authority forks.
- [log-awid-registry-unavailable](log-awid-registry-unavailable.md) — log every AWID-unavailable/alias-lookup failure (UTC, cwd, command, error, retry, health) to docs/awid-registry-unavailable-log.md; retry and keep driving.
- [run-aw-only-from-instance-home](run-aw-only-from-instance-home.md) — run aw ONLY from the instance home (repo root = grace, a different identity); never batch git+aw in one shell; "agent not found" is usually wrong-cwd, not a registry outage.
- [dont-reopen-converged-decisions](dont-reopen-converged-decisions.md) — once the team converges + commits on a functionally-fine choice, freeze it; don't re-open for a marginal detail; a coordinator flip-flop costs more thrash than the gain.
- [correctness-over-momentum](correctness-over-momentum.md) — optimize for getting it right, not activity; don't manufacture busywork to avoid idle; drive to done-RIGHT, slow the cadence, write+pressure-test high-risk plans before executing.
- [aweb-deploy-topology](aweb-deploy-topology.md) — app.aweb.ai IS ac's deployment; the aweb server is bundled into ac's release image from source; aweb changes ship via an ac v* release, not a separate aweb pipeline (deploy owner = ac-coordinator).
- [dont-assert-business-facts-messy-isnt-unneeded](dont-assert-business-facts-messy-isnt-unneeded.md) — don't assert pricing/roadmap/what's-needed facts (verify or ask Juan); and messy/unproven/sprawl ≠ unneeded — clean+consolidate needed machinery, don't cut it.
- [app-emit-path-binding-canonical](app-emit-path-binding-canonical.md) — app-emit signed path is mount-dependent + LOCKED: /api/v1/events/app hosted (ac mounts under /api; raw_request_target uses full-external raw_path), /v1 = standalone vector fixture; don't "fix" folio to /v1; the live emit is the empirical arbiter over coordinator theory.
- [awid-cert-controller-only-revoke](awid-cert-controller-only-revoke.md) — awid certs are deliberately controller-only for add AND revoke; the issuer_did_key column + revoke-broadening was investigated and SCRAPPED as YAGNI (2026-06-21); don't reopen unless member-mediated invites become scope; AC orphan bugs aabq.10/aabq.9 survive independently.

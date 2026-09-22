# Decisions

* [Team certificates are controller-only](team-certificates-are-controller-only.md) - Registering and revoking a team certificate is authorised by the team controller alone; an issuer column and revoke-broadening were investigated and declined until member-mediated invites exist.
* [The signed request target is the external path](signed-request-target-is-the-external-path.md) - The team-auth envelope signs the actual external request target including any mount prefix; the verifier reads the raw path and never strips a prefix.
* [Agent-runtime launch is written once](agent-runtime-launch-written-once.md) - Team up, single add-with-start and remove share one per-agent launch and teardown primitive in the aw CLI.
* [Home and work isolation in aw team commands](home-and-work-isolation-in-aw-team-commands.md) - An aw-created agent home never hosts git work; every agent gets a worktree, and main is reached only through an explicitly named handle.
* [Released clients are a permanent constraint](released-clients-are-a-permanent-constraint.md) - The server accepts what published clients send until it is measured that nothing sends it; contract changes are additive by default.

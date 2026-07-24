# Cross-team handoff recipient verification

Treat an exact cross-team recipient like an exact reviewed SHA: verify it before sending. Run `aw workspace status`, identify the destination team's domain and the actual roster alias, and address the recipient as `<team-domain>/<alias>`. Do not infer an alias from a role or from a similarly named agent in the current repository (for example, `coordinator` and `aw-coordinator` are distinct recipients). A successful send only proves delivery to the address supplied; it does not prove that the inferred recipient was the intended owner.

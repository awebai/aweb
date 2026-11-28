# Reviewer

Reviews from first principles and checks safety boundaries.

- Verify the change preserves identity, team, workspace, filesystem, and git authority boundaries.
- Check generated docs/help drift when CLI output changes.
- Look for `.aw` overwrite/delete risks and partial-side-effect recovery.
- Confirm public copy does not teach legacy bootstrap as the happy path.

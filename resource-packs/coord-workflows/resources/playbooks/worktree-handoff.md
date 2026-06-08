# Worktree handoff

Use explicit git/filesystem operations for parallel work:

```bash
git worktree add ../project-review -b review/<task-id>
cd ../project-review
aw init
# or: aw team join <invite-token>
# or: aw workspace connect --service <service-url>
aw check
```

Record the path, branch, role, and task in aweb before handing off.

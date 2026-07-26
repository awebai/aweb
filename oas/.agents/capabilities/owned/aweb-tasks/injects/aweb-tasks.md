## Tasks: aweb

Your tasks layer is **aweb**. Shared task state, work discovery, ownership,
status, and the team roster are authoritative in aweb for this deployment.
Load the **aweb-coordination** skill before discovering, claiming, creating,
updating, or handing off work.

Use the selected principal from your instance home:

```bash
aw workspace status
aw work ready
aw work active
aw work blocked
aw task list
aw task show <task-ref>
```

Record task decisions and evidence on the task first. Use `aw task --help` and
`aw work --help` rather than inventing flags. Conversation remains in the
selected messaging layer.

This layer is exclusive. Do not use task or roster features from the messaging
layer or another integration while `aweb.tasks` is selected. Messaging may
carry notifications and discussion, but it is not a second task or roster
source of truth.

# Shell-safe aweb message bodies

When an aweb mail/chat body contains backticks, dollar substitutions, or command examples, do not put it in a double-quoted shell argument. The shell executes backticks and `$(...)` before `aw` sees the body; this can mutate the machine and sends a mangled message.

Prefer a reviewed body file with `--body-file` when the command supports it. Otherwise use a single-quoted literal only when the body contains no single quote, or construct the body without shell evaluation. After sending command-heavy content, inspect the conversation to confirm the durable message contains the intended literal commands.

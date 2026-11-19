# Runtime hook configuration

Hook installation and removal edit only aw-owned handlers and preserve all other
JSON bytes, including numeric precision and escapes. Duplicate keys and malformed
hook structures refuse with a repair instruction before any file is replaced.
Custom matchers remain user-owned. Legacy notification migration respects the
requested confirmation policy. Settings and agent instructions use the shared
atomic file writer, preserving the resolved file's mode.

Notification cooldown files belong in the selected CLI state directory at 0600.
Failure to write a cooldown does not suppress a working notification.

`aw activity hook uninstall --codex` removes the unscoped activity handlers aw
installs, preserving other handlers and user fields. `aw init --remove-notify-hook`
removes exact fallback notification handlers under aw's default matcher, including
legacy unscoped entries, preserving custom matchers and making a backup.

JSON refusals name the settings file and the specific syntax, duplicate-key or
object-shape repair. Init continues its other actions and reports the hook as
not installed. Install/remove round trips preserve user bytes, including whitespace.

Aw hook editors serialize their read/edit/replace operation with a stable sidecar
lock in the settings directory. The settings snapshot is read under that lock;
installation reads it again after any confirmation prompt. Editors outside aw
do not share this lock. Explicit cleanup also checks its snapshot before writing
and keeps the original backup when that check refuses a concurrent edit.

The lock serializes aw against aw; an external editor can still save between the
reread and the atomic write, so the remaining window is the write operation,
not the duration of the confirmation prompt.

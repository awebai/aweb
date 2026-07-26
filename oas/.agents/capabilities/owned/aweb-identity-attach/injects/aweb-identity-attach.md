# Experimental aweb identity binding

This capability is **experimental and internal** until an ordinary golden journey passes.
Before spawning, run `oas aweb-identity status --soul <name> --json` and act only on
`ready`. The status result is advisory and cannot prevent OAS from launching an
unbound instance after a hook failure because current OAS hooks are not required hooks. Never describe this integration as fail-closed or production-ready.

Durable resident provisioning is not an available setup option. A refusal creates no
identity resource; its single `next_action` is the complete supported guidance.

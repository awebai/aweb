from __future__ import annotations


HOSTED_HANDLE_DOMAIN_SUFFIX = ".aweb.ai"


def _valid_handle_namespace(namespace: str) -> bool:
    return (
        bool(namespace)
        and not namespace.startswith(".")
        and not namespace.endswith(".")
        and ".." not in namespace
        and "@" not in namespace
    )


def normalize_hosted_handle_reference(value: str, *, require_agent: bool = False) -> str:
    """Normalize consumer @handle references to canonical aweb.ai addresses.

    ``@jane/c3po`` is the public shorthand for ``jane.aweb.ai/c3po``.
    Dotted handles are already explicit namespaces, so ``@acme.com/bot``
    normalizes to ``acme.com/bot`` rather than ``acme.com.aweb.ai/bot``.
    Agent names keep their case because aweb agent names are case-sensitive.
    """
    raw = str(value or "").strip()
    if not raw.startswith("@"):
        return raw

    ref = raw[1:].strip()
    if not ref:
        return raw

    namespace, sep, agent_name = ref.partition("/")
    namespace = namespace.strip().lower()
    if not _valid_handle_namespace(namespace):
        return raw
    if "." not in namespace:
        namespace = f"{namespace}{HOSTED_HANDLE_DOMAIN_SUFFIX}"

    if not sep:
        return raw if require_agent else namespace

    agent_name = agent_name.strip()
    if not agent_name or "/" in agent_name:
        return raw
    return f"{namespace}/{agent_name}"

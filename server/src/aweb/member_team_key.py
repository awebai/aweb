"""A member is a member under its team's current key.

The server records, on each member's agents row, the team key under which it
last accepted that member's certificate (accepted_team_did_key). The team's
current key is the key the server admitted the team with, moved only by the
namespace controller's act (teams.team_did_key, aweb.team_key_pins). A member
whose recorded key is not the current one is refused wherever it is looked up,
so changing a team's key removes every member until each holds a certificate
under the new key. A row with no recorded certificate predates the recording
of certificates and is judged as before.
"""

from __future__ import annotations


def current_team_key_sql(agent: str) -> str:
    """SQL for the current key of the team of the agents row aliased ``agent``."""
    return f"(SELECT team_did_key FROM {{{{tables.teams}}}} WHERE team_id = {agent}.team_id)"


def member_key_columns_sql(agent: str) -> str:
    """The columns member_key_current reads, from the agents row aliased ``agent``."""
    return f"{agent}.accepted_team_did_key, {current_team_key_sql(agent)} AS current_team_did_key"


def member_key_current_sql(agent: str) -> str:
    """SQL predicate: the agents row aliased ``agent`` is a member under its
    team's current key."""
    return (
        f"({agent}.certificate_id IS NULL"
        f" OR {agent}.accepted_team_did_key = {current_team_key_sql(agent)})"
    )


def member_key_current(row) -> bool:
    """Whether the member ``row`` (an agents row read with
    member_key_columns_sql) was accepted under its team's current key. A row
    read without those columns is not."""
    if not str(row.get("certificate_id") or "").strip():
        return True
    accepted = str(row.get("accepted_team_did_key") or "").strip()
    return bool(accepted) and accepted == str(row.get("current_team_did_key") or "").strip()


def grant_issuer_current(row) -> bool:
    """Whether the grant ``row``, joined to its subject's agents row
    (certificate_id and member_key_columns_sql), still has its issuing
    certificate: the subject is a member under the current key and that
    member's certificate is the one the grant was issued from. A credential
    issued from a superseded certificate does not return."""
    if not member_key_current(row):
        return False
    issuer = str(row.get("issued_by_certificate_id") or "").strip()
    current = str(row.get("certificate_id") or "").strip()
    return not issuer or not current or issuer == current

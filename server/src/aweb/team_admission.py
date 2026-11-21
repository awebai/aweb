"""First native team admission; later pin movement belongs to team_key_pins."""

from pgdbm import AsyncDatabaseManager, TransactionManager

from awid.team_ids import parse_team_id


async def admit_team(
    *, db: AsyncDatabaseManager | TransactionManager, team_id: str, team_did_key: str,
) -> bool:
    """Persist already-authorized first admission, returning whether inserted.

    Parse native identity names and leave an existing row completely unchanged,
    including its pin and accepted-act timestamp. A registry read or possession
    of a controller secret is not authority supplied by this storage operation.
    It performs no network I/O and can share the host's native transaction.
    """
    try:
        namespace, name = parse_team_id(team_id)
    except ValueError as exc:
        raise ValueError("Invalid team ID. Use a canonical <team>:<namespace> team ID, then retry.") from exc
    inserted = await db.fetch_value(
        """INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (team_id) DO NOTHING RETURNING team_id""",
        team_id, namespace, name, team_did_key,
    )
    return inserted is not None

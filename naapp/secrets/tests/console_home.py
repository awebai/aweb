"""The console home's banner for tests whose console has nothing to report."""

from aweb_naapp.console import ConsoleSession


async def no_banner(session: ConsoleSession) -> str:
    return ""

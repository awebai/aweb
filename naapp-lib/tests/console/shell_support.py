"""An app's console on the shared browser shell, for the shell's tests: real
B3 passkeys on the shared credential recorder, real console sessions, the
shared login and credential routes, and a test brand whose copy and
stylesheet are the app's own."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from fastapi import FastAPI

from aweb_naapp.console import (
    ClientIdentity,
    ConsoleSessions,
    LoginLimiter,
    apply_console_migrations,
    console_login_router,
    credential_router,
)
from aweb_naapp.console.browser import (
    Ceremony,
    CeremonyCopy,
    ConsoleBrand,
    ConsoleShell,
    SignInCopy,
)
from aweb_naapp.runtime.origins import split_origins
from tests.runtime.credential_audit.support import World

STYLESHEET = "body { margin: 0; }\nmain { max-width: 40rem; margin: auto; padding: 1rem; }\n"
CSRF_KEY = "example.console.csrf"

SIGN_IN = SignInCopy(
    title="Example sign-in",
    heading="Sign in to Example",
    scoped_hint="Use your passkey to sign in to Example.",
    unscoped_hint="Open the sign-in link Example sent you.",
    button="Sign in to Example",
    waiting="Example is waiting for your passkey.",
    failed="Example could not sign you in.",
    sign_out_failed="Example could not sign you out.",
    reauth_heading="Sign in to Example again",
    reauth_text="This tab needs its own Example sign-in.",
    reauth_link="Sign in to Example with your passkey",
)

CEREMONIES = CeremonyCopy(
    enrolment=Ceremony(
        title="Set up an Example passkey",
        explanation="Create the passkey you will use for Example.",
        action="Create Example passkey",
        done="Your Example passkey is ready.",
    ),
    contact_proof=Ceremony(
        title="Confirm your Example contact",
        explanation="Confirm that Example can reach you here.",
        action="Confirm Example contact",
        done="Example has confirmed your contact.",
    ),
    missing_link="Open the Example link from your email.",
    completing="Example is finishing your request.",
    failed="Example could not finish. Request a new link.",
    continue_link="Continue to Example sign-in",
)

BRAND = ConsoleBrand(product="Example", csrf_key=CSRF_KEY, stylesheet=STYLESHEET, sign_in=SIGN_IN)

HOME = (
    '<h1 id="home">Example console</h1>'
    '<form id="logout" action="/logout" method="post">'
    '<button type="submit">Sign out of Example</button></form>'
    '<p id="notice" role="status" aria-live="polite"></p>'
)


async def admits(world: World, scope: str) -> bool:
    return bool(
        await world.db.fetch_value(
            "SELECT EXISTS (SELECT 1 FROM {{tables.example_bindings}} WHERE scope = $1)", scope
        )
    )


@dataclass
class ShellApp:
    shell: ConsoleShell
    sessions: ConsoleSessions
    human: FastAPI
    app: FastAPI


async def shell_app(world: World, *, human_origin: str, agent_origin: str) -> ShellApp:
    """The app's two origins, with the shell's pages on the human one."""
    await apply_console_migrations(world.db)

    async def admitted(scope: str) -> bool:
        return await admits(world, scope)

    sessions = ConsoleSessions(world.db, passkeys=world.passkeys, scopes=admitted)
    limiter = LoginLimiter(
        world.db, client_identity=ClientIdentity(), limit=50, window=timedelta(minutes=1)
    )
    shell = ConsoleShell(BRAND)
    human = FastAPI()
    human.include_router(console_login_router(sessions=sessions, limiter=limiter))
    human.include_router(credential_router(passkeys=world.passkeys, recorder=world.recorder))
    human.include_router(
        shell.router(sessions=sessions, home_title="Example console", home_html=HOME)
    )
    human.include_router(shell.bootstrap_router(CEREMONIES))
    app = split_origins(FastAPI(), human, agent_origin=agent_origin, human_origin=human_origin)
    return ShellApp(shell, sessions, human, app)

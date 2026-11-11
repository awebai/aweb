"""The logs console's pages: the shared browser shell in logs' brand.

A reader enrols from the link in its mail, signs in with its passkey and
reaches its home on the console origin, from which the viewer
(:mod:`aweb_logs.console_ui.viewer`) reads its team's log. Every word, the
stylesheet and the tab CSRF storage key ``aweb.logs.console.csrf`` are logs'
own.
"""

from pathlib import Path

from aweb_naapp.console import ConsoleSession, console_assets_router
from aweb_naapp.console.browser import (
    Ceremony,
    CeremonyCopy,
    ConsoleBrand,
    ConsoleShell,
    SignInCopy,
)
from fastapi import APIRouter

from aweb_logs.console_ui.viewer import viewer_router
from aweb_logs.read_routes import ReaderReads

SHELL = ConsoleShell(
    ConsoleBrand(
        product="Logs",
        csrf_key="aweb.logs.console.csrf",
        stylesheet=(Path(__file__).parent / "style.css").read_text(),
        sign_in=SignInCopy(
            title="Sign in",
            heading="Sign in to Logs",
            scoped_hint="Use your passkey to continue.",
            unscoped_hint="Open your Logs sign-in link to continue.",
            button="Sign in with a passkey",
            waiting="Waiting for your passkey…",
            failed="Sign-in could not be completed. Try your passkey again.",
            sign_out_failed="Sign-out could not be completed. Try again.",
            reauth_heading="Sign in to continue",
            reauth_text="Sign in again in this tab to read your team’s log.",
            reauth_link="Sign in with your passkey",
        ),
    )
)

CEREMONIES = CeremonyCopy(
    enrolment=Ceremony(
        title="Set up your passkey",
        explanation="Use the link from your email to create your passkey for Logs.",
        action="Set up passkey",
        done="Passkey is ready.",
    ),
    contact_proof=Ceremony(
        title="Confirm your email address",
        explanation="Confirm that you can receive email here. The waiting period still applies.",
        action="Confirm email address",
        done="Email address confirmed. The waiting period still applies.",
    ),
    missing_link="Open the link from your email to continue.",
    completing="Completing your request…",
    failed="Unable to finish. Try again, or request a new link.",
    continue_link="Continue to sign in",
)

HOME = (
    '<div class="heading"><h1>Logs</h1>'
    '<form id="logout" action="/logout" method="post">'
    '<button type="submit" class="secondary">Sign out</button></form></div>'
    "<p>You are signed in as a reader of your team’s log.</p>"
    '<ul class="home-links">'
    '<li><a href="/events">Events</a><span>Browse and filter what was recorded.</span></li>'
    '<li><a href="/follow">Follow</a><span>Watch new events as they are recorded.</span></li>'
    '<li><a href="/integrity">Integrity</a><span>Check the signed chain and what this'
    " server observed of delivery.</span></li></ul>"
    '<p id="notice" role="status" aria-live="polite"></p>'
)


async def home(session: ConsoleSession) -> str:
    """A reader's home: the same for every reader."""
    return HOME


def console_pages_router(reads: ReaderReads) -> APIRouter:
    """The console origin's pages and assets: home, sign-in, the link
    ceremonies, the viewer, the shell's scripts and the toolkit stylesheet."""
    router = APIRouter()
    router.include_router(SHELL.router(sessions=reads.sessions, home_title="Logs", home=home))
    router.include_router(SHELL.bootstrap_router(CEREMONIES))
    router.include_router(viewer_router(SHELL, reads))
    router.include_router(console_assets_router())
    return router

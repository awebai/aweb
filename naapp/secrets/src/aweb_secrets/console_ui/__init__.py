"""Human-origin browser shell; authentication and mutations stay with S4/B3.

Mount alongside owner_console_router on the human app only. The scope in a
setup/sign-in link is a locator, never authority. Custody owns the destination
pages and app composition owns the mount.

The shell is the shared one (aweb_naapp.console.browser) in secrets' brand:
its name, copy, stylesheet and tab CSRF storage key aweb.secrets.console.csrf.
"""

from pathlib import Path

from aweb_naapp.console import ConsoleSessions
from aweb_naapp.console.browser import ConsoleBrand, ConsoleShell, SignInCopy, login_redirect
from fastapi import APIRouter

SHELL = ConsoleShell(
    ConsoleBrand(
        product="Secrets",
        csrf_key="aweb.secrets.console.csrf",
        stylesheet=(Path(__file__).parent / "style.css").read_text(),
        sign_in=SignInCopy(
            title="Sign in",
            heading="Sign in to Secrets",
            scoped_hint="Use your passkey to continue.",
            unscoped_hint="Open your owner or approver sign-in link to continue.",
            button="Sign in with a passkey",
            waiting="Waiting for your passkey…",
            failed="Sign-in could not be completed. Try your passkey again.",
            sign_out_failed="Sign-out could not be completed. Try again.",
            reauth_heading="Sign in to make changes",
            reauth_text="Sign in again in this tab to make changes.",
            reauth_link="Sign in with your passkey",
        ),
    )
)

_page = SHELL.page
console_page = SHELL.console_page
_login_redirect = login_redirect

HOME = (
    '<div class="heading"><h1>Secrets console</h1>'
    '<form id="logout" action="/logout" method="post">'
    '<button type="submit" class="secondary">Sign out</button></form></div>'
    "<p>Manage your team’s secrets and the people and agents who can use them.</p>"
    '<nav aria-label="Console"><a href="/secrets/new">Create a secret</a>'
    '<a href="/grants/new">Grant access to a role</a>'
    '<a href="/approvals">Review approvals</a>'
    '<a href="/activity">View activity</a></nav>'
    '<p id="notice" role="status" aria-live="polite"></p>'
)


def console_ui_router(*, sessions: ConsoleSessions) -> APIRouter:
    """GET shell/login and static assets; mount only on the human origin."""
    return SHELL.router(sessions=sessions, home_title="Console", home_html=HOME)

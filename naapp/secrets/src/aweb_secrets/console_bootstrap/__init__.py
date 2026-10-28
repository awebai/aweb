"""Anonymous fragment locators for the existing B3 POST ceremonies.

Mount on the human origin alongside owner_console_router. These pages create
no console session; completion authority remains in the service's ceremony.
"""

from aweb_naapp.console.browser import Ceremony, CeremonyCopy
from fastapi import APIRouter

from aweb_secrets.console_ui import SHELL

CEREMONIES = CeremonyCopy(
    enrolment=Ceremony(
        title="Set up your passkey",
        explanation="Use the link from your email to create your passkey for Secrets.",
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


def console_bootstrap_router() -> APIRouter:
    return SHELL.bootstrap_router(CEREMONIES)

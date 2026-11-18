"""Canonical native serving state, including hosts carrying one resource ref."""


def native_application_state(state):
    resources = getattr(state, "native_resources", None)
    return resources.api_app.state if resources is not None else state

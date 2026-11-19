"""Actual rendered policy files for holder component controls."""

from approval_service.gate import render_policy


def policy_file(path, organisation, level="passkey"):
    section = (
        {}
        if level is None
        else {
            "service": "https://approval.example",
            "require": {"organisation.human.add": level},
        }
    )
    path.write_bytes(render_policy(organisation, section))
    return path

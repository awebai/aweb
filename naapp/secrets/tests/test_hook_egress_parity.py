"""secrets and logs read the same hook egress settings, each under its own
prefix, and build their hook guard with the same shared builder."""

import pytest
from aweb_logs.config import LogsSettings
from aweb_naapp.runtime.hook_egress import HookEgressSettings

from aweb_secrets.deployment import DeploymentSettings


@pytest.mark.parametrize("service", [DeploymentSettings, LogsSettings])
def test_a_deployed_service_reads_every_shared_hook_egress_setting_unchanged(service) -> None:
    assert issubclass(service, HookEgressSettings)
    for name, shared in HookEgressSettings.model_fields.items():
        field = service.model_fields[name]
        assert (field.annotation, field.default) == (shared.annotation, shared.default), name

"""secrets and logs read the same operator network settings, each under its
own prefix, and build their guard with the same shared builder."""

import pytest
from aweb_logs.config import LogsSettings
from aweb_naapp.runtime.operator_egress import OperatorNetworkSettings

from aweb_secrets.deployment import DeploymentSettings


@pytest.mark.parametrize("service", [DeploymentSettings, LogsSettings])
def test_a_deployed_service_reads_every_shared_operator_network_setting_unchanged(service) -> None:
    assert issubclass(service, OperatorNetworkSettings)
    for name, shared in OperatorNetworkSettings.model_fields.items():
        field = service.model_fields[name]
        assert (field.annotation, field.default) == (shared.annotation, shared.default), name

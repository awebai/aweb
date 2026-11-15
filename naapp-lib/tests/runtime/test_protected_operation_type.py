"""One concrete typed operation, without unreleased compatibility aliases."""

from aweb_naapp.runtime import protected_signer
from aweb_naapp.runtime.protected_signer import catalog, types


def test_all_operations_use_one_concrete_type_and_one_definition_type():
    assert len(protected_signer.__all__) == len(set(protected_signer.__all__))
    assert protected_signer.OwnerActOperation.__name__ == "OwnerActOperation"
    for module in (protected_signer, types):
        assert not hasattr(module, "RevokeHumanRole")
        assert not hasattr(module, "CatalogOperation")
    assert not hasattr(catalog, "OperationSpec")
    assert catalog.OperationDefinition.__name__ == "OperationDefinition"

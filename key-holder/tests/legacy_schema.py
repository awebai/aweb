"""Remove the version-six objects when constructing a historical fixture."""


def remove_attestation_inventory(db):
    db.execute("DROP VIEW active_attestation_inventory")
    db.execute("DROP TRIGGER attestation_inventory_remove_deleted")
    db.execute("DROP TRIGGER attestation_inventory_remove_retired")
    db.execute("DROP TABLE attestation_inventory")

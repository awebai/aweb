CREATE TABLE attestation_inventory (
    namespace TEXT NOT NULL,
    person TEXT NOT NULL,
    credential TEXT NOT NULL,
    assessment TEXT NOT NULL,
    PRIMARY KEY (namespace, person, credential)
);

CREATE VIEW active_attestation_inventory AS
SELECT inventory.*
FROM attestation_inventory AS inventory
JOIN enrollments ON enrollments.person = inventory.person
WHERE enrollments.active = 1 AND enrollments.retired_at IS NULL;

CREATE TRIGGER attestation_inventory_remove_deleted
AFTER DELETE ON enrollments
BEGIN
    DELETE FROM attestation_inventory
    WHERE namespace = (SELECT organisation FROM configuration) AND person = OLD.person;
END;

CREATE TRIGGER attestation_inventory_remove_retired
AFTER UPDATE OF retired_at ON enrollments
WHEN OLD.retired_at IS NULL AND NEW.retired_at IS NOT NULL
BEGIN
    DELETE FROM attestation_inventory
    WHERE namespace = (SELECT organisation FROM configuration) AND person = NEW.person;
END;

PRAGMA user_version = 6;

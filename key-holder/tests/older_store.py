"""A store at an earlier schema version, made by the ordered migrations alone."""

from importlib.resources import files

from aweb_key_holder.keys import KeyStore

MIGRATIONS = {
    2: "002_enrollment.sql",
    3: "003_issuing.sql",
    4: "004_person_history.sql",
}


def older_store(directory, *, version):
    """Keys and configuration come from KeyStore.create; only its schema stops early."""

    class OlderStore(KeyStore):
        def migrate(self):
            with self._connection() as db:
                for number in range(2, version + 1):
                    db.executescript(
                        files("aweb_key_holder")
                        .joinpath("migrations", MIGRATIONS[number])
                        .read_text()
                    )

    OlderStore.create(directory, organisation="example.test")
    return KeyStore(directory)

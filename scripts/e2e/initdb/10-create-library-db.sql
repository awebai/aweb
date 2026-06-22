-- Library owns its own database (it migrates into the public schema), so it
-- cannot share the `aweb` database where awid (schema `awid`) and the aweb
-- server (public schema) live. Create a dedicated `library` database in the
-- same postgres instance. Runs once on first init; with the tmpfs data volume
-- every `docker compose up` is a fresh init.
CREATE DATABASE library OWNER aweb;

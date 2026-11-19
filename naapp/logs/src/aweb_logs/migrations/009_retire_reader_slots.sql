-- Reader slots are retired (human-role-holders.md): a reader is the current
-- holder of logs.reader, recorded in the shared holding store and named by the
-- owner's human-role act, never by a slot drawn for a contact. No slot was ever
-- a holding, so none carries over; its indexes go with it.
DROP TABLE IF EXISTS {{tables.readers}};

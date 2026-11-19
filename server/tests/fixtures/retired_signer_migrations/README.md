# Retired signer migration inputs

These files are archived test inputs, not installed migrations. The server SQL
is unchanged from `server-v1.27.51rc2`; the shared SQL is unchanged from
`7731a3e157^` (the last tree before the signer package was removed).
The upgrade control applies these through pgdbm, including their real module
ledgers, before applying the cleanup migrations from the surviving packages.

# aw Go CLI plugin dispatch status

As of `aw` 1.32.9, the Go CLI has a generic installed-manifest dispatcher. `aw plugin install <manifest>` installs a trusted app manifest and `aw plugin list` shows installed apps. Discover the live app surface through CLI help — `aw <app> --help`, `aw <app> <verb> --help`, or `aw <app> help <verb>` — rather than reading raw manifest `input_schema` fields. Nested help is rendered from the validated installed manifest without contacting the app origin and reports accepted flags, requiredness, request location, and body-file behavior.

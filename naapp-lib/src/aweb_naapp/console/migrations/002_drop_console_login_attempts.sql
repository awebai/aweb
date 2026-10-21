-- Login attempts are limited by the shared token buckets (aweb_naapp.ratelimit),
-- so the fixed-window table goes.
DROP TABLE IF EXISTS {{tables.console_login_attempts}};

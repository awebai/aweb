-- Rate buckets: one row per (bucket, key), written in the caller's transaction.
-- A bucket holds `tokens` as of `refilled_at`; `full_at` is when it refills to
-- the capacity it was last written with. A row past `full_at` equals an absent
-- one, which reads as full, so a sweep may delete it. The table lives in the
-- calling app's own schema: two apps never share rows.

CREATE TABLE IF NOT EXISTS {{tables.rate_buckets}} (
    bucket       TEXT NOT NULL,
    key          TEXT NOT NULL,
    tokens       DOUBLE PRECISION NOT NULL,
    refilled_at  TIMESTAMPTZ NOT NULL,
    full_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (bucket, key)
);

CREATE INDEX IF NOT EXISTS idx_rate_buckets_full_at
    ON {{tables.rate_buckets}} (full_at);

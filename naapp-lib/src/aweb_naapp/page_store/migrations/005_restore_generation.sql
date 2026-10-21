-- Each startup assigns a fresh generation before admitting writes. A UUID
-- cannot repeat when an older content backup is restored.
CREATE TABLE {{tables.page_store_generation}} (
    singleton BOOLEAN PRIMARY KEY CHECK(singleton),
    generation UUID NOT NULL
);

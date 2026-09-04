-- A realm's message bundles, one row per locale.
--
-- **One nullable text column holding the whole document, not a row per key.**
-- Measured 2026-09-03 on a live 26.7.1, and the three facts that decide it are:
--
--   * the key order is the contract and it is not derivable from the keys -
--     `PUT .../{locale}/{key}` appends and `POST .../{locale}` re-buckets the
--     whole document through a Java map, so two writes on one locale leave two
--     different orders for the same key set;
--   * `POST .../{locale}` with an **empty body** answers 204 and leaves a
--     locale with no document at all, which `GET /localization` lists and every
--     read of answers `500 unknown_error` for ever - a state a row-per-key
--     table cannot express, because "no rows" is also what `{}` looks like;
--   * `{}` is a different body with a different outcome: 204, and the locale
--     reads back `{}`.
--
-- So the column is nullable and the two states are NULL and '[]'. It is the
-- shape Keycloak's own REALM_LOCALIZATIONS has, arrived at from the wire rather
-- than from the schema.
--
-- The document is a JSON array of {"Key","Value"} objects rather than a JSON
-- object, because a JSON object round-tripped through Go's encoding/json is
-- sorted on the way out and the order is the whole point. The `client`,
-- `user_entity` and `realm` tables next door already store JSON in a TEXT
-- column, so nothing new is being introduced here except the null.
--
-- ON DELETE CASCADE is what removes a deleted realm's bundles; bootstrap.
-- DeleteRealm needs no clause of its own, the way it needs none for keys,
-- sessions or organizations.
CREATE TABLE realm_localization (
    realm_id TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    locale   TEXT NOT NULL,
    texts    TEXT,
    PRIMARY KEY (realm_id, locale)
);

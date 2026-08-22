CREATE TABLE realm_key (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    algorithm   TEXT NOT NULL,
    key_use     TEXT NOT NULL DEFAULT '',
    private_key BLOB NOT NULL,
    certificate BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    UNIQUE (realm_id, algorithm)
);

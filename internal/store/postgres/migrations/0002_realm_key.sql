CREATE TABLE realm_key (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    algorithm   TEXT NOT NULL,
    key_use     TEXT NOT NULL DEFAULT '',
    private_key BYTEA NOT NULL,
    certificate BYTEA NOT NULL,
    created_at  BIGINT NOT NULL,
    UNIQUE (realm_id, algorithm)
);

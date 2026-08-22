CREATE TABLE user_session (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES user_entity(id) ON DELETE CASCADE,
    username     TEXT NOT NULL,
    started_at   BIGINT NOT NULL,
    last_refresh BIGINT NOT NULL,
    expires_at   BIGINT NOT NULL
);

CREATE TABLE client_session (
    id              TEXT PRIMARY KEY,
    user_session_id TEXT NOT NULL REFERENCES user_session(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES client(id) ON DELETE CASCADE,
    scope           TEXT NOT NULL DEFAULT '',
    started_at      BIGINT NOT NULL,
    UNIQUE (user_session_id, client_id)
);

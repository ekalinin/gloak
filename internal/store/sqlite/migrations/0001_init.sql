CREATE TABLE realm (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL UNIQUE,
    enabled                INTEGER NOT NULL DEFAULT 1,
    access_token_lifespan  INTEGER NOT NULL DEFAULT 60,
    refresh_token_lifespan INTEGER NOT NULL DEFAULT 1800
);

CREATE TABLE client (
    id                           TEXT PRIMARY KEY,
    realm_id                     TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id                    TEXT NOT NULL,
    name                         TEXT NOT NULL DEFAULT '',
    enabled                      INTEGER NOT NULL DEFAULT 1,
    public_client                INTEGER NOT NULL DEFAULT 0,
    secret                       TEXT NOT NULL DEFAULT '',
    standard_flow_enabled        INTEGER NOT NULL DEFAULT 1,
    direct_access_grants_enabled INTEGER NOT NULL DEFAULT 0,
    service_accounts_enabled     INTEGER NOT NULL DEFAULT 0,
    redirect_uris                TEXT NOT NULL DEFAULT '[]',
    web_origins                  TEXT NOT NULL DEFAULT '[]',
    attributes                   TEXT NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, client_id)
);

CREATE TABLE user_entity (
    id                TEXT PRIMARY KEY,
    realm_id          TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    username          TEXT NOT NULL,
    email             TEXT NOT NULL DEFAULT '',
    email_verified    INTEGER NOT NULL DEFAULT 0,
    enabled           INTEGER NOT NULL DEFAULT 1,
    first_name        TEXT NOT NULL DEFAULT '',
    last_name         TEXT NOT NULL DEFAULT '',
    created_timestamp INTEGER NOT NULL DEFAULT 0,
    attributes        TEXT NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, username)
);

CREATE TABLE credential (
    id                    TEXT PRIMARY KEY,
    user_id               TEXT NOT NULL REFERENCES user_entity(id) ON DELETE CASCADE,
    type                  TEXT NOT NULL,
    created_date          INTEGER NOT NULL DEFAULT 0,
    algorithm             TEXT NOT NULL DEFAULT '',
    hash_iterations       INTEGER NOT NULL DEFAULT 0,
    additional_parameters TEXT NOT NULL DEFAULT '{}',
    salt                  BLOB,
    hash_value            BLOB,
    UNIQUE (user_id, type)
);

CREATE TABLE keycloak_role (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    composite   INTEGER NOT NULL DEFAULT 0,
    UNIQUE (realm_id, client_id, name)
);

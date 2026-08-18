CREATE TABLE realm (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL UNIQUE,
    enabled                BOOLEAN NOT NULL DEFAULT TRUE,
    access_token_lifespan  BIGINT NOT NULL DEFAULT 60,
    refresh_token_lifespan BIGINT NOT NULL DEFAULT 1800
);

CREATE TABLE client (
    id                           TEXT PRIMARY KEY,
    realm_id                     TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id                    TEXT NOT NULL,
    name                         TEXT NOT NULL DEFAULT '',
    enabled                      BOOLEAN NOT NULL DEFAULT TRUE,
    public_client                BOOLEAN NOT NULL DEFAULT FALSE,
    secret                       TEXT NOT NULL DEFAULT '',
    standard_flow_enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    direct_access_grants_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    service_accounts_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    redirect_uris                JSONB NOT NULL DEFAULT '[]',
    web_origins                  JSONB NOT NULL DEFAULT '[]',
    attributes                   JSONB NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, client_id)
);

CREATE TABLE user_entity (
    id                TEXT PRIMARY KEY,
    realm_id          TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    username          TEXT NOT NULL,
    email             TEXT NOT NULL DEFAULT '',
    email_verified    BOOLEAN NOT NULL DEFAULT FALSE,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    first_name        TEXT NOT NULL DEFAULT '',
    last_name         TEXT NOT NULL DEFAULT '',
    created_timestamp BIGINT NOT NULL DEFAULT 0,
    attributes        JSONB NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, username)
);

CREATE TABLE credential (
    id                    TEXT PRIMARY KEY,
    user_id               TEXT NOT NULL REFERENCES user_entity(id) ON DELETE CASCADE,
    type                  TEXT NOT NULL,
    created_date          BIGINT NOT NULL DEFAULT 0,
    algorithm             TEXT NOT NULL DEFAULT '',
    hash_iterations       INTEGER NOT NULL DEFAULT 0,
    additional_parameters JSONB NOT NULL DEFAULT '{}',
    salt                  BYTEA,
    hash_value            BYTEA,
    UNIQUE (user_id, type)
);

CREATE TABLE keycloak_role (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    composite   BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (realm_id, client_id, name)
);

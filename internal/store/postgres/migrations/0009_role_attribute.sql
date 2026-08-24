CREATE TABLE role_attribute (
    role_id TEXT NOT NULL REFERENCES keycloak_role (id) ON DELETE CASCADE,
    name    TEXT NOT NULL,
    value   TEXT NOT NULL,
    ordinal INTEGER NOT NULL
);

CREATE INDEX role_attribute_role_id ON role_attribute (role_id);

CREATE TABLE user_role_mapping (
    user_id TEXT NOT NULL REFERENCES user_entity(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES keycloak_role(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE composite_role (
    composite  TEXT NOT NULL REFERENCES keycloak_role(id) ON DELETE CASCADE,
    child_role TEXT NOT NULL REFERENCES keycloak_role(id) ON DELETE CASCADE,
    PRIMARY KEY (composite, child_role)
);

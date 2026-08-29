-- Roles assigned to a group.
--
-- The user's mirror is user_role_mapping in 0004; this is deliberately a second
-- table rather than one with a nullable holder column. The two are read by
-- different routes with different guards, and a shared table invites a query
-- that forgets which kind of holder it meant.
CREATE TABLE group_role_mapping (
    group_id TEXT NOT NULL REFERENCES keycloak_group (id) ON DELETE CASCADE,
    role_id  TEXT NOT NULL REFERENCES keycloak_role (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, role_id)
);

CREATE INDEX group_role_mapping_role ON group_role_mapping (role_id);

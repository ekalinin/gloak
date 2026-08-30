-- Scope mappings: the roles a client or a client scope may put into a token.
--
-- Not a role anybody holds. A scope mapping is a **filter** - it decides which
-- of the roles a user already has survive into a token issued for that client -
-- which is why it is a third pair of tables beside user_role_mapping and
-- group_role_mapping rather than a third kind of holder on either.
--
-- Two tables and not one, for a different reason from 0011's. One table cannot
-- carry a foreign key to two parents, and the pair of nullable holder columns
-- that would replace it is the shape 0011 refused. Keycloak's own schema splits
-- them the same way and for the same reason: SCOPE_MAPPING(CLIENT_ID, ROLE_ID)
-- and CLIENT_SCOPE_ROLE_MAPPING(SCOPE_ID, ROLE_ID).
--
-- Tables and not a JSON column, which is what 0014 and 0015 chose for the
-- protocol mappers next door. Two things differ. A mapping's whole identity is
-- a role id, so deleting the role has to delete the mapping - measured: a realm
-- role deleted while mapped left the scope with one fewer, and only a real
-- foreign key does that. And the served order is **not** reproducible: these
-- arrays come back in the realm's role-listing order, which AGENTS.md records
-- as unstable across container starts, so there is no recorded order for a
-- column to preserve.
CREATE TABLE scope_mapping (
    client_id TEXT NOT NULL REFERENCES client (id) ON DELETE CASCADE,
    role_id   TEXT NOT NULL REFERENCES keycloak_role (id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, role_id)
);

CREATE INDEX scope_mapping_role ON scope_mapping (role_id);

CREATE TABLE client_scope_role_mapping (
    client_scope_id TEXT NOT NULL REFERENCES client_scope (id) ON DELETE CASCADE,
    role_id         TEXT NOT NULL REFERENCES keycloak_role (id) ON DELETE CASCADE,
    PRIMARY KEY (client_scope_id, role_id)
);

CREATE INDEX client_scope_role_mapping_role ON client_scope_role_mapping (role_id);

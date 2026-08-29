-- A realm's client scopes, and the two membership sets that hang off them.
--
-- attributes and protocol_mappers are JSON columns rather than tables. Both are
-- served back in Keycloak's own key order, which a normalised table cannot
-- carry without a per-row ordinal, and neither is written by any endpoint in
-- this cut: the Protocol Mappers tag is the next one. A column is the smallest
-- thing that lets a client scope be reproduced from stored state.
CREATE TABLE client_scope (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT '',
    attributes TEXT NOT NULL DEFAULT '{}',
    protocol_mappers TEXT NOT NULL DEFAULT '[]',
    UNIQUE (realm_id, name)
);

-- The realm's own default and optional client scopes: what a client created
-- without lists of its own inherits.
--
-- One table with a flag, not two tables, and the primary key is on
-- (realm_id, client_scope_id) rather than including default_scope. That is
-- measured: PUT of a scope already in the *other* list answered 409
-- `Duplicate resource error`, so a scope cannot be in both, and the constraint
-- is what makes that a conflict rather than a silent second row.
CREATE TABLE realm_default_client_scope (
    realm_id TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_scope_id TEXT NOT NULL REFERENCES client_scope (id) ON DELETE CASCADE,
    default_scope INTEGER NOT NULL,
    PRIMARY KEY (realm_id, client_scope_id)
);

CREATE INDEX realm_default_client_scope_scope
    ON realm_default_client_scope (client_scope_id);

-- A client's own default and optional client scopes.
--
-- Same shape and the same reason, from the other direction: PUT of a scope the
-- client already held as an optional scope answered 204 and did not move it,
-- so a client's two lists are one attachment carrying a flag.
CREATE TABLE client_client_scope (
    client_id TEXT NOT NULL REFERENCES client (id) ON DELETE CASCADE,
    client_scope_id TEXT NOT NULL REFERENCES client_scope (id) ON DELETE CASCADE,
    default_scope INTEGER NOT NULL,
    PRIMARY KEY (client_id, client_scope_id)
);

CREATE INDEX client_client_scope_scope ON client_client_scope (client_scope_id);

-- The two columns 0005 added are dropped rather than left dead.
--
-- They held the client's scope **names**. A client's attachment has to survive
-- the scope being renamed - measured: renaming a client scope changed the name
-- in every client's list and in both of the realm's, and kept the attachment -
-- which a name cannot do. client_client_scope holds ids and is now the only
-- truth; model.Client still carries names because that is what the
-- representation serialises, and the client repository derives them by joining.
--
-- Leaving the columns behind would be the second truth AGENTS.md's boundary
-- table warns about, one write away from disagreeing with the join.
ALTER TABLE client DROP COLUMN default_client_scopes;
ALTER TABLE client DROP COLUMN optional_client_scopes;

-- A realm's authentication flow model: the object the Authentication Management
-- tag's `flows`, `executions` and `config` families address, and the object
-- `internal/oidc`'s browser login now reads two rows of.
--
-- Measured 2026-09-03 on a live 26.7.1. A realm created through
-- POST /admin/realms has **20 flows (7 top-level, 13 sub), 55 execution rows
-- and 4 authenticator configs**; master has 17, 48 and 4. The difference is
-- exactly three flows and two execution rows - the organization family - which
-- is why the seed carries a not-in-master flag rather than two tables. See
-- docs/superpowers/plans/2026-09-03-f103-authentication-flows.md §2.
--
-- **`alias` is nullable, and it has to be.** POST /flows/{alias}/copy with no
-- `newName`, and POST /flows/{alias}/executions/flow with no `alias`, both
-- answer 201 and create a flow whose representation has no `alias` key at all.
-- A NOT NULL column would refuse a request Keycloak accepts. Reproducing a
-- resource the API cannot name afterwards is the same decision F97 and F159
-- record; tidying it is what breaks the copy.
--
-- **There is no `ordinal` on authentication_execution.** The listing order
-- inside one parent is `priority` ascending, and raise-priority *swaps* two
-- rows' priorities rather than renumbering, so priority is the order and a
-- second column would be a second truth. `authentication_flow` does carry one,
-- because GET /flows is insertion-ordered and flow ids are random UUIDs that do
-- not sort that way - the `component` and `client_initial_access` device.
--
-- **`config` is JSON text rather than a map column** for the reason F95 gives:
-- a Go map[string]string marshals sorted and Keycloak's order is not sorted.
-- The four seeded configs have one key each so nothing is observable in them,
-- but a caller's POST /config may send several.
--
-- `authenticator` and `flow_id` are both nullable because the three shapes of a
-- row are measured: a leaf carries an authenticator and no flow, a pure
-- sub-flow row carries a flow and no authenticator, and the `registration`
-- flow's single row carries **both** - `registration-page-form` pointing at the
-- `registration form` sub-flow. A schema that made them exclusive would refuse
-- the seed.
--
-- ON DELETE CASCADE removes a deleted realm's rows; bootstrap.DeleteRealm needs
-- no clause of its own. config_id has no foreign key on purpose: deleting a
-- config leaves the execution addressable and its pointer is cleared by the
-- handler, which is the measured behaviour of DELETE /config/{id}.
CREATE TABLE authentication_flow (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    alias       TEXT,
    description TEXT NOT NULL DEFAULT '',
    provider_id TEXT NOT NULL,
    top_level   INTEGER NOT NULL,
    built_in    INTEGER NOT NULL,
    ordinal     INTEGER NOT NULL
);

CREATE INDEX idx_authentication_flow_realm ON authentication_flow (realm_id);

CREATE TABLE authentication_config (
    id       TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    alias    TEXT NOT NULL DEFAULT '',
    config   TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_authentication_config_realm ON authentication_config (realm_id);

CREATE TABLE authentication_execution (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    parent_flow_id TEXT NOT NULL REFERENCES authentication_flow (id) ON DELETE CASCADE,
    authenticator  TEXT,
    flow_id        TEXT,
    config_id      TEXT,
    requirement    TEXT NOT NULL,
    priority       INTEGER NOT NULL
);

CREATE INDEX idx_authentication_execution_realm ON authentication_execution (realm_id);
CREATE INDEX idx_authentication_execution_parent ON authentication_execution (parent_flow_id);

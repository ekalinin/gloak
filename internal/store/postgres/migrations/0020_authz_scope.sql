-- An authorization scope of a resource server.
--
-- The foreign key is onto authz_resource_server rather than onto client, and
-- the cascade is the point: the resource server's row *is* the client's
-- authorizationServicesEnabled flag, and turning that flag off was measured
-- destroying the settings. A scope that outlived the flag would offer a state
-- Keycloak cannot reach - the same argument 0019 makes for having no `enabled`
-- column, applied one level down.
--
-- id is TEXT and is not a UUID. Measured 2026-09-01: `POST .../scope` with
-- `{"id":"zzz","name":"idshape"}` answered 201 and created a scope whose id is
-- the three bytes `zzz`. The body's id wins on this endpoint - the third such
-- endpoint after POST /clients and POST /client-scopes - so a generated id is
-- a fallback and never a correction.
--
-- The unique constraint is on (resource_server_id, name) and **not** on name
-- alone: `alpha` was created in two resource servers at once, and reading one
-- server's scope id through the other is a 404. It is what makes
-- `POST .../scope` with an id that names nothing and a name that is taken a
-- 409 `Duplicate resource error` rather than a second row.
--
-- icon_uri and display_name are NOT NULL and default to the empty string
-- rather than being nullable. Both are omitted from every representation when
-- empty - measured, a scope created with only a name comes back
-- `{"id":...,"name":...}` and nothing else - so absent and empty are one state
-- on the wire and there is no third for NULL to carry.
--
-- ordinal exists because **one set of scopes has two reads and two orders**.
-- `GET .../scope` comes back sorted by name, byte-wise:
-- `ALPHAX, Bravo, brand-new, charlie, delta, idshape` on a container where
-- they were created in another order. `GET .../settings` comes back in
-- creation order: four scopes created `zulu, yankee, xray, whiskey` - the
-- reverse of name order - came back exactly that way, and deleting `xray` and
-- recreating it moved it to the **end**. Both are reproducible and measured,
-- so the export's order is stored and served rather than masked, which is the
-- same decision realm_default_client_scope.ordinal records. It is assigned
-- `COALESCE(MAX(ordinal), -1) + 1` per resource server, as that table's writer
-- already does.
CREATE TABLE authz_scope (
    id                 TEXT PRIMARY KEY,
    resource_server_id TEXT NOT NULL REFERENCES authz_resource_server (client_id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    icon_uri           TEXT NOT NULL,
    display_name       TEXT NOT NULL,
    ordinal            INTEGER NOT NULL,
    UNIQUE (resource_server_id, name)
);

CREATE INDEX authz_scope_resource_server ON authz_scope (resource_server_id);

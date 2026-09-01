-- A protected resource of a resource server, and its three child collections.
--
-- The foreign key is onto authz_resource_server rather than onto client, and
-- the cascade is the point, for the reason 0020 gives: the resource server's
-- row *is* the client's authorizationServicesEnabled flag, and turning that
-- flag off was measured destroying the settings.
--
-- id is TEXT and is not a UUID. Measured 2026-09-01: `POST .../resource` with
-- `{"_id":"myownid","name":"idwins"}` answered 201 and created a resource whose
-- id is the eight bytes `myownid`. The wire name is `_id`; a body carrying
-- `id` is refused by the strict decoder. So a generated id is a fallback and
-- never a correction, exactly as on authz_scope.
--
-- The primary key is global and the unique constraint is on
-- (resource_server_id, name), which is the pair of constraints the server was
-- measured enforcing: creating a resource with an id another resource server
-- already holds is a 409 `Duplicate resource error`, and `r1` exists in two
-- resource servers at once. **Unlike the scope family, the losing create does
-- no damage**: after the 409 the owning server's listing, its per-id read and
-- its settings export all still answer 200, where a colliding scope id leaves
-- the other server's listing a 400 and its settings a 500. F131 is about the
-- scope family and does not generalise here; this schema reproduces what was
-- measured rather than diverging from it.
--
-- display_name, type and icon_uri are NOT NULL and default to the empty string
-- rather than being nullable. All three are omitted from every representation
-- when empty - measured on a resource created with only a name - so absent and
-- empty are one state on the wire and there is no third for NULL to carry.
--
-- ordinal exists because **one set of resources has two reads and two orders**,
-- which is authz_scope.ordinal's reason on a second family: `GET .../resource`
-- comes back sorted by name and `GET .../settings` comes back in creation
-- order. `GET .../scope/{id}/resources` is a third consumer and it serves
-- creation order too. It is assigned `COALESCE(MAX(ordinal), -1) + 1` per
-- resource server, as authz_scope's writer already does.
CREATE TABLE authz_resource (
    id                   TEXT PRIMARY KEY,
    resource_server_id   TEXT NOT NULL REFERENCES authz_resource_server (client_id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    display_name         TEXT NOT NULL,
    type                 TEXT NOT NULL,
    icon_uri             TEXT NOT NULL,
    owner_managed_access INTEGER NOT NULL,
    ordinal              INTEGER NOT NULL,
    UNIQUE (resource_server_id, name)
);

CREATE INDEX authz_resource_resource_server ON authz_resource (resource_server_id);

-- The three child tables all carry an ordinal, and the reason is different on
-- each of the first two.
--
-- `uris` is a Java HashSet and `attributes` a Java HashMap, and **their chains
-- run in opposite directions**: three uris sharing one bucket came back in
-- request order and three attribute keys sharing one bucket came back in
-- reverse request order, measured on one body on one container. Neither order
-- can be recovered from a Go map, so both are stored as they arrived and
-- internal/admin decides the wire order from that.
--
-- authz_resource_scope's ordinal is the third case and it is the weakest: the
-- set is keyed on the scope's *name*, and three names sharing a bucket came
-- back in two different orders from two requests, so nothing observable says
-- what the chain was. It is stored anyway because it is what
-- `GET .../resource/{id}/scopes` has to serve in some order, and request order
-- is the only one the wire ever showed.
CREATE TABLE authz_resource_uri (
    resource_id TEXT NOT NULL REFERENCES authz_resource (id) ON DELETE CASCADE,
    value       TEXT NOT NULL,
    ordinal     INTEGER NOT NULL,
    PRIMARY KEY (resource_id, value)
);

CREATE TABLE authz_resource_attribute (
    resource_id TEXT NOT NULL REFERENCES authz_resource (id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    value       TEXT NOT NULL,
    ordinal     INTEGER NOT NULL
);

CREATE INDEX authz_resource_attribute_resource ON authz_resource_attribute (resource_id);

CREATE TABLE authz_resource_scope (
    resource_id TEXT NOT NULL REFERENCES authz_resource (id) ON DELETE CASCADE,
    scope_id    TEXT NOT NULL REFERENCES authz_scope (id) ON DELETE CASCADE,
    ordinal     INTEGER NOT NULL,
    PRIMARY KEY (resource_id, scope_id)
);

CREATE INDEX authz_resource_scope_scope ON authz_resource_scope (scope_id);

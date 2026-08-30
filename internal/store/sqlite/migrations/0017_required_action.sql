-- A realm's registered required action providers: the fourteen rows
-- GET /admin/realms/{realm}/authentication/required-actions serves.
--
-- The primary key is a server-minted id and **not** (realm_id, alias), which
-- looks like the obvious key and cannot carry the measured behaviour.
-- PUT /required-actions/{alias} writes the body's alias over the row's, so
-- `PUT` with `{}` renames a row to the empty string: it then vanishes from
-- every alias-addressed route and stays in the listing as a six-key object
-- with no `alias` key at all, enabled false and priority 0. Keycloak's own
-- defect, reproduced as far as the admin API reaches. Keyed by alias that row
-- could not exist, and two of them could not coexist.
--
-- For the same reason there is no UNIQUE (realm_id, alias): nothing measured
-- says a duplicate alias is refused, and inventing a constraint would be
-- inventing a 409 nobody has seen.
--
-- name is nullable because the key is **absent** rather than empty when it was
-- never set - a row registered through POST /register-required-action with no
-- `name` reads back with six keys - while an explicitly empty name reads back
-- as `""`. NULL and '' are two different observable answers here.
--
-- config is a JSON column for the reason client_scope.attributes is one: it is
-- served back in Keycloak's own key order, which a normalised table cannot
-- carry without a per-row ordinal.
CREATE TABLE required_action_provider (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    alias TEXT NOT NULL DEFAULT '',
    name TEXT,
    provider_id TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    default_action INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 0,
    config TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX required_action_provider_realm
    ON required_action_provider (realm_id, priority);

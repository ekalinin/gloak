-- A policy of a resource server, and its two child collections.
--
-- **One table holds both families.** A permission is a policy whose type is
-- `resource`, `scope` or `uma`, and the two are one row in one table on
-- 26.7.1: `GET .../policy?permission=true` and `GET .../permission` returned
-- the same rows one key apart, measured 2026-09-02. A second table would make
-- that filter a union and the `policyId` filter ambiguous.
--
-- id is TEXT and is not a UUID, for authz_scope's and authz_resource's reason:
-- `POST .../policy` with `{"id":"x",...}` answered 201 and created a policy
-- whose id is the single byte `x`. Unlike authz_resource the id does **not**
-- upsert - a repeat of an id this resource server already holds is a 409
-- `Duplicate resource error`, so the primary key is the whole of the rule and
-- internal/admin adds no lookup in front of it.
--
-- The primary key is global and the unique constraint is on
-- (resource_server_id, name), which is what the server was measured enforcing:
-- an id another resource server holds is a 409 and the **other** server is
-- undamaged - its listing and its settings both still answered 200. That is the
-- resource family's behaviour, not F131's scope-family corruption.
--
-- description and owner are NOT NULL and default to the empty string rather
-- than being nullable. `description` is omitted from every representation when
-- empty and `owner` is never served at all - it is echoed by the create and
-- dropped by every read - so absent and empty are one state on the wire and
-- there is no third for NULL to carry.
--
-- ordinal exists because **one set of policies has two orders**, which is
-- authz_scope.ordinal's reason on a third family: `GET .../policy` comes back
-- sorted by name byte-wise, and `GET .../settings` comes back in creation order
-- with the `resource` and `scope` rows moved to the end. Neither order can be
-- recovered from the other, and the export's partition is **not** the
-- `permission=true` filter's - `uma` is a permission to the filter and a policy
-- to the export.
CREATE TABLE authz_policy (
    id                 TEXT PRIMARY KEY,
    resource_server_id TEXT NOT NULL REFERENCES authz_resource_server (client_id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL,
    type               TEXT NOT NULL,
    logic              TEXT NOT NULL,
    decision_strategy  TEXT NOT NULL,
    owner              TEXT NOT NULL,
    ordinal            INTEGER NOT NULL,
    UNIQUE (resource_server_id, name)
);

CREATE INDEX authz_policy_resource_server ON authz_policy (resource_server_id);

-- The config is a Java map whose serialised key order is part of the contract:
-- `javamap.SizedKeyOrder(len(config), keys)` places every measured key set
-- exactly and `javamap.KeyOrder` gets two of eight wrong. Neither order can be
-- recovered from a Go map, so the entries are stored in the order they arrived
-- and internal/admin computes the wire order from that - authz_resource's
-- attributes one table along.
--
-- The value is TEXT and holds JSON for the four keys that carry a collection
-- (`roles`, `clients`, `groups`, `applyPolicies`), because that is what the
-- server serves: `config.roles` is the **string**
-- `"[{\"id\":\"...\",\"required\":false}]"`, not a nested array.
CREATE TABLE authz_policy_config (
    policy_id TEXT NOT NULL REFERENCES authz_policy (id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    value     TEXT NOT NULL,
    ordinal   INTEGER NOT NULL,
    PRIMARY KEY (policy_id, name)
);

-- A policy's three association sets in one table, keyed by what they point at.
--
-- One table rather than three because all three are the same shape - an ordered
-- list of ids within one policy - and because the two listings filter on two of
-- them (`?resource=` and `?scope=`) with one comparison each. `kind` is
-- 'policy', 'resource' or 'scope'.
--
-- **They are not symmetrical on the wire and that is measured.** `policies` and
-- `resources` are echoed by the create and served by no read; `scopes` is
-- served by exactly one type's typed view - `uma`'s, always, `[]` when empty -
-- and by no other. The rows are kept for all three because the listings filter
-- on them and because `GET .../settings` synthesises an aggregate policy's
-- `config.applyPolicies` back out of them, by name.
--
-- There is no foreign key onto authz_policy for the target: `kind = 'policy'`
-- would need one and the other two would need different ones, and a partial
-- reference is worse than none. The rows go with their owning policy through
-- the cascade above, which is the only lifetime that matters.
CREATE TABLE authz_policy_association (
    policy_id TEXT NOT NULL REFERENCES authz_policy (id) ON DELETE CASCADE,
    kind      TEXT NOT NULL,
    target_id TEXT NOT NULL,
    ordinal   INTEGER NOT NULL,
    PRIMARY KEY (policy_id, kind, target_id)
);

CREATE INDEX authz_policy_association_target ON authz_policy_association (kind, target_id);

-- A realm's identity provider mappers, the rows
-- `/admin/realms/{realm}/identity-provider/instances/{alias}/mappers` serves.
--
-- **alias is a column and not a foreign key onto identity_provider.** Measured
-- 2026-09-02, three separate requests:
--
--   * the create stores the body's `identityProviderAlias` and echoes it raw;
--   * a `PUT` can set it to a value no provider in the realm has, and does;
--   * the three single-mapper routes never look at the path's alias - a mapper
--     created under `ord-idp` was read through `ord-idp2`'s path with a 200 and
--     deleted through it with a 204, while `ord-idp2`'s own listing stayed `[]`.
--
-- A REFERENCES clause would refuse the second of those and an ON DELETE CASCADE
-- would invent a rule the third says does not exist. The realm is the only
-- container this row really has, so realm_id is the only foreign key.
--
-- The unique constraint is (realm_id, alias, name) because that is what the
-- measured conflict is: a second mapper of the same name under the same alias
-- answers `400 {"errorMessage":"Failed to add mapper 'x' to identity provider
-- [oidc]."}`. Note the status - a **400**, not the 409 the rest of this API
-- gives a duplicate - and note that the sentence names the provider's
-- `providerId` where the route carries its alias.
--
-- id is the primary key and the body's `id` wins on create, which is the fifth
-- endpoint in this API with that rule, so a generated id is a fallback and never
-- a correction.
--
-- ordinal records the creation order. It is **not** Keycloak's serving order:
-- five mappers created `zzz, mmm, aaa, qqq, bbb` came back `bbb, zzz, qqq, mmm,
-- aaa`, reproducibly within one container and reproducible nowhere else, since
-- the ids that decide it are minted UUIDs. The conformance case masks the array
-- and this column is what keeps a driver deterministic where the server is not -
-- the same argument the component table's ordinal already makes.
CREATE TABLE identity_provider_mapper (
    id       TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    alias    TEXT NOT NULL,
    name     TEXT NOT NULL,
    mapper   TEXT NOT NULL,
    ordinal  INTEGER NOT NULL,
    UNIQUE (realm_id, alias, name)
);

CREATE INDEX identity_provider_mapper_realm ON identity_provider_mapper (realm_id, alias);

-- Single-valued, like identity_provider_config and unlike component_config: a
-- mapper's config is `{"role":"offline_access"}` on the wire where a
-- component's is `{"priority":["100"]}`.
--
-- **The key order is javamap.SizedKeyOrder**, the same constructor the parent
-- provider's config uses and the opposite of the component's - ten measured key
-- sets, all ten placed, javamap.KeyOrder getting six of the ten wrong. One key
-- set was sent to both families on one container and came back two ways:
-- `{priority, enabled, active}` is `priority active enabled` here and
-- `active priority enabled` on a component.
--
-- ordinal carries the insertion order, which SizedKeyOrder takes as an argument
-- and which a bucket collision chains by. It is load-bearing rather than
-- defensive here: `{zz, aa, mm}` and `{aa, mm, zz}` were both sent and both came
-- back in the order they went in, so those three share a bucket and the request
-- order is the only thing that decides them.
CREATE TABLE identity_provider_mapper_config (
    mapper_id TEXT NOT NULL REFERENCES identity_provider_mapper (id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    value     TEXT NOT NULL,
    ordinal   INTEGER NOT NULL
);

CREATE INDEX identity_provider_mapper_config_mapper ON identity_provider_mapper_config (mapper_id);

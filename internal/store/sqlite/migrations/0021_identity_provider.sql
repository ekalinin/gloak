-- A realm's identity providers and its SPI components.
--
-- Two families in one migration because they arrive together and neither
-- references the other: `Identity Providers` and `Component` are the two
-- chapters of P9, and splitting them would give one of them a number the other
-- would then have to skip.
--
-- ## identity_provider
--
-- **alias is nullable and that is measured, not defensive.** `PUT
-- .../identity-provider/instances/{alias}` with a body carrying no `alias`
-- answers 204 and clears it: the listing then serves the row with **no `alias`
-- key at all**, sorted first, and nothing can address it again. The rename
-- guard is `Identity Provider alias cannot be changed`, and a null alias is not
-- a change, so the check passes and the write lands. Keycloak's own defect,
-- reproduced, and a NOT NULL column would make the state unreachable.
--
-- The primary key is internal_id and the unique constraint is
-- (realm_id, alias). The two are not the same thing: every route in the family
-- addresses a provider by its **alias** while the representation carries both,
-- and `POST` was measured honouring the body's `internalId` - a create naming
-- `11111111-...` produced a provider with exactly that id, the third such
-- endpoint after POST /clients and POST /client-scopes. So a generated id is a
-- fallback and never a correction.
--
-- The six flag columns are nullable INTEGER because **absent and false are two
-- measured answers on the wire**: a create that never mentions `trustEmail`
-- reads back with no such key, and one sending `"trustEmail":false` reads back
-- carrying `false`. Six fields, one rule, and a NOT NULL DEFAULT 0 would make
-- every provider look as though it had been configured. `enabled` is the one
-- boolean that is not tri-state - it is always serialised, defaulting to true -
-- so it is NOT NULL.
--
-- display_name and first_broker_login_flow_alias are NOT NULL DEFAULT '': both
-- are omitted from the representation when empty, so absent and empty are one
-- state and there is no third for NULL to carry. That is the opposite of the
-- six flags above, on the same row.
CREATE TABLE identity_provider (
    internal_id                   TEXT PRIMARY KEY,
    realm_id                      TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    alias                         TEXT,
    display_name                  TEXT NOT NULL DEFAULT '',
    provider_id                   TEXT NOT NULL,
    enabled                       INTEGER NOT NULL,
    trust_email                   INTEGER,
    store_token                   INTEGER,
    add_read_token_role_on_create INTEGER,
    authenticate_by_default       INTEGER,
    link_only                     INTEGER,
    hide_on_login                 INTEGER,
    first_broker_login_flow_alias TEXT NOT NULL DEFAULT '',
    UNIQUE (realm_id, alias)
);

CREATE INDEX identity_provider_realm ON identity_provider (realm_id);

-- The config is a table rather than a JSON column for the reason
-- organization_attribute is one: its wire order is a Java map's and a Go map
-- would sort it. **This one is javamap.SizedKeyOrder**, the `7n/4` constructor
-- a protocol mapper's config uses, confirmed on nine measured key sets where
-- javamap.KeyOrder gets four wrong. The component config next door is the
-- other constructor, which is why the two families do not share a serialiser.
--
-- ordinal is kept even though the order is computed, because a bucket
-- collision chains in **insertion order** and nothing observable recovers it -
-- the same reason organization_attribute has one.
--
-- The value is single-valued here and multivalued on component_config below.
-- That is the wire's shape, not a simplification: an identity provider's
-- config is `{"clientId":"cid"}` and a component's is `{"priority":["100"]}`.
CREATE TABLE identity_provider_config (
    internal_id TEXT NOT NULL REFERENCES identity_provider (internal_id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    value       TEXT NOT NULL,
    ordinal     INTEGER NOT NULL
);

CREATE INDEX identity_provider_config_provider ON identity_provider_config (internal_id);

-- ## component
--
-- The generic SPI-component store. A realm created through POST /admin/realms
-- has **fourteen** rows and master has **fifteen**, measured on one container:
-- four key providers, ten client-registration policies, and - on master alone -
-- the declarative user profile.
--
-- **name is nullable** because that fifteenth row has no `name` key at all
-- where every other component has one. It is the only place this family
-- distinguishes absent from empty, and it is exactly the row a created realm
-- does not get.
--
-- parent_id is a plain column and not a self-reference. Every component a
-- default install has is parented on the **realm's own internal id**, which is
-- not a row in this table, so a foreign key onto component would refuse every
-- bootstrapped row. `GET .../components/{realm id}` is measured
-- `404 {"error":"Could not find component"}`, which says the realm is a parent
-- and not a component.
--
-- sub_type is NOT NULL DEFAULT '' rather than nullable: it is `anonymous` or
-- `authenticated` on the ten policies and simply absent elsewhere, and the
-- representation omits it when empty, so absent and empty are one state.
--
-- ordinal exists and **is not the serving order**. The listing's row order was
-- measured having no reproducible order at all: two realms created minutes
-- apart on one container returned the same fourteen rows in two entirely
-- different orders, matching neither insertion, name, id nor provider. The
-- column records the order bootstrap wrote them in so that a driver is
-- deterministic where the server is not - the conformance case masks the array
-- rather than asserting either.
CREATE TABLE component (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    name          TEXT,
    provider_id   TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    parent_id     TEXT NOT NULL,
    sub_type      TEXT NOT NULL DEFAULT '',
    ordinal       INTEGER NOT NULL
);

CREATE INDEX component_realm ON component (realm_id);

-- Multivalued, unlike identity_provider_config: every component config value on
-- the wire is a JSON array even when it holds one string. **The key order here
-- is javamap.KeyOrder**, the no-argument constructor - six of seven measured
-- key sets are placed exactly and SizedKeyOrder gets two of those six wrong.
-- The seventh is twelve LDAP keys with three colliding pairs, which neither
-- function can place and which nothing in this cut serves.
CREATE TABLE component_config (
    component_id TEXT NOT NULL REFERENCES component (id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    value        TEXT NOT NULL,
    ordinal      INTEGER NOT NULL
);

CREATE INDEX component_config_component ON component_config (component_id);

-- Organizations, their e-mail domains and their attributes.
--
-- **Two unique constraints rather than one**, because the two collisions do not
-- answer alike. A duplicate name is
-- `409 {"errorMessage":"A organization with the same name already exists."}`
-- and a duplicate alias is
-- `409 {"errorMessage":"A organization with the same alias already exists"}` -
-- the same status and the same sentence bar a full stop, measured on one verb
-- of one resource. The handler has to know which one fired and cannot infer it
-- from a single constraint, so the schema keeps them apart.
--
-- alias is a stored column and not a view over name. It defaults to the name at
-- creation and is immutable afterwards: a PUT that changes it, or that omits it
-- after a rename, is a 400 rather than a silent re-derivation. A generated
-- column would make that 400 unreachable.
--
-- enabled is INTEGER in both drivers, following client_client_scope.default_scope
-- next door: the two migrations are byte-identical per driver on purpose, and a
-- BOOLEAN here would be the first place they diverge.
-- **description is nullable and redirect_url is not**, which is not tidiness
-- and not an oversight. A create sending `{"description":"","redirectUrl":""}`
-- reads back carrying `"description":""` and **no** `redirectUrl` key at all:
-- two fields, one empty value, opposite answers. So description has to tell
-- "never set" from "set to nothing" and redirectUrl does not, and NULL is what
-- carries that difference. It is RequiredActionProvider.Name's rule on another
-- resource, and the same reason applies - a NOT NULL column collapses the two
-- states the representation distinguishes.
CREATE TABLE organization (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    alias        TEXT NOT NULL,
    enabled      INTEGER NOT NULL,
    description  TEXT,
    redirect_url TEXT NOT NULL DEFAULT '',
    UNIQUE (realm_id, name),
    UNIQUE (realm_id, alias)
);

-- A domain is a row rather than a field on the organization because the
-- duplicate-domain check is **realm-wide**: the measured 400 names the *other*
-- organization the domain is already linked to, so answering it means querying
-- across the realm rather than comparing one organization's own list.
--
-- There is no UNIQUE (realm_id, name) here because realm_id is not on this
-- table; the query goes through organization. Adding the column to get the
-- constraint would put the realm in two places that could disagree.
CREATE TABLE organization_domain (
    organization_id TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    verified        INTEGER NOT NULL,
    ordinal         INTEGER NOT NULL
);

CREATE INDEX organization_domain_org ON organization_domain (organization_id);

-- ordinal for the reason group_attribute has one: the order came off the wire
-- and a Go map would sort it. An organization's attributes are multivalued -
-- `{"k":["v"]}` - so the ordinal orders the values within a name as well as the
-- names themselves.
CREATE TABLE organization_attribute (
    organization_id TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    value           TEXT NOT NULL,
    ordinal         INTEGER NOT NULL
);

CREATE INDEX organization_attribute_org ON organization_attribute (organization_id);

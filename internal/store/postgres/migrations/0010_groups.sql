-- Groups, and the users in them.
--
-- There is no path column on purpose. A group's path is derived from its
-- ancestry: renaming a parent was measured moving every descendant's path while
-- leaving their names alone, so a stored path would have to be rewritten for the
-- whole subtree on every rename and the first missed rewrite is a divergence
-- nothing would catch. See "Groups: P2's third cut" section 5.
--
-- parent_id is empty rather than NULL for a top-level group, matching
-- keycloak_role.client_id next door: the two mean the same thing - "this row
-- has no owner above it" - and a schema that spells it two ways invites a
-- comparison that is right for one and wrong for the other.
--
-- **It therefore carries no REFERENCES clause and there is no cascade on it.**
-- A foreign key cannot point at '' , so the empty-string convention and a
-- self-referencing key are mutually exclusive. GroupRepo.Delete removes the
-- subtree itself, and its doc comment says so; the two tables below do cascade,
-- because their keys are real.
CREATE TABLE keycloak_group (
    id        TEXT PRIMARY KEY,
    realm_id  TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    parent_id TEXT NOT NULL DEFAULT '',
    name      TEXT NOT NULL,
    -- Unique within a parent, not within a realm: the measured 409 says "Top
    -- level group named 'x' already exists", so it is the level that collides.
    UNIQUE (realm_id, parent_id, name)
);

CREATE INDEX keycloak_group_parent ON keycloak_group (realm_id, parent_id);

CREATE TABLE group_attribute (
    group_id TEXT NOT NULL REFERENCES keycloak_group (id) ON DELETE CASCADE,
    name     TEXT NOT NULL,
    value    TEXT NOT NULL,
    ordinal  INTEGER NOT NULL
);

CREATE INDEX group_attribute_group_id ON group_attribute (group_id);

-- Membership is direct only. A user in a child was measured **not** being a
-- member of its parent, so nothing here walks upwards and nothing should.
CREATE TABLE group_membership (
    group_id TEXT NOT NULL REFERENCES keycloak_group (id) ON DELETE CASCADE,
    user_id  TEXT NOT NULL REFERENCES user_entity (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX group_membership_user ON group_membership (user_id);

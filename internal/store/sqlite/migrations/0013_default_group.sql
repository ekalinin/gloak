-- A realm's default groups: the groups every user created in it joins.
--
-- The cascade off keycloak_group is measured, not tidiness. Deleting a group
-- that was a default group was measured removing it from
-- GET /admin/realms/{realm}/default-groups, so the join row cannot outlive the
-- group it names.
--
-- The primary key is what makes PUT idempotent without a read first: the same
-- group added twice was measured answering 204 both times and appearing once.
CREATE TABLE realm_default_group (
    realm_id TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES keycloak_group (id) ON DELETE CASCADE,
    PRIMARY KEY (realm_id, group_id)
);

CREATE INDEX realm_default_group_group ON realm_default_group (group_id);

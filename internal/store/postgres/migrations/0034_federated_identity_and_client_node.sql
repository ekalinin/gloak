-- Two small tables that have nothing to do with each other beyond arriving in
-- one cut: a user's links to identity providers, and a client's registered
-- cluster nodes.
--
-- `federated_identity` is what `GET /users/{user-id}/federated-identity` reads
-- and its `POST`/`DELETE` siblings write.
--
-- **The alias is not a foreign key and must not become one.** Measured
-- 2026-09-05 on a live 26.7.1: `POST .../federated-identity/nosuchidp` for an
-- alias that is not a registered identity provider answers **204** and stores
-- the link - a repeat answers 409 and a `DELETE` answers 204, so the row is
-- really there - while the listing beside it answers `[]`. Registering an
-- identity provider with that alias afterwards makes the same stored row
-- appear, unchanged. So the **write** does not check the alias and the **read**
-- filters on it, and a REFERENCES clause here would turn a measured 204 into a
-- 404.
--
-- `external_user_id` and `external_username` are NOT NULL and default to the
-- empty string rather than being nullable, because a `POST` with the body `{}`
-- is a measured 204 whose row comes back as `{"identityProvider":"fi2"}` - the
-- two keys are omitted from the wire when empty, and `omitempty` on the
-- representation is what does that. A nullable column would put the same
-- decision in two places.
--
-- `seq` exists because the listing's order is **insertion order**, measured on
-- two links added in a known order. Neither the alias nor the external id
-- reproduces it, so nothing derivable can stand in for it. It is the
-- `client_initial_access` table's `ordinal` under another name; the name
-- differs because this one is per user rather than per realm.
--
-- The primary key is (realm_id, user_id, identity_provider) because the
-- measured 409 - `User is already linked with provider` - fires on exactly that
-- triple: one user may hold links to many providers and one link per provider.
CREATE TABLE federated_identity (
    realm_id          TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    user_id           TEXT NOT NULL REFERENCES user_entity (id) ON DELETE CASCADE,
    identity_provider TEXT NOT NULL,
    external_user_id  TEXT NOT NULL,
    external_username TEXT NOT NULL,
    seq               INTEGER NOT NULL,
    PRIMARY KEY (realm_id, user_id, identity_provider)
);

CREATE INDEX idx_federated_identity_user ON federated_identity (user_id);

-- `client_node` is the client's `registeredNodes` map, which the client
-- representation serves and `POST`/`DELETE .../clients/{uuid}/nodes` write.
--
-- `registered_at` is **unix seconds**, not milliseconds: a node registered on
-- 2026-09-05 came back as `{"node1.example.com":1788641822}`, ten digits, where
-- every timestamp the user representation carries is thirteen.
--
-- The map is **absent** from the representation when a client has no node -
-- measured with `has("registeredNodes")` false on a bootstrapped client - which
-- is `omitempty` on the field rather than anything this table does. There is no
-- row to distinguish "empty" from "unset" and no measurement asks for one.
CREATE TABLE client_node (
    client_id     TEXT NOT NULL REFERENCES client (id) ON DELETE CASCADE,
    node          TEXT NOT NULL,
    registered_at INTEGER NOT NULL,
    PRIMARY KEY (client_id, node)
);

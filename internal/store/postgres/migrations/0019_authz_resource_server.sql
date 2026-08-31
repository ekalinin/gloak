-- A client's authorization services settings.
--
-- **The row's existence is the flag.** `authorizationServicesEnabled` on a
-- client representation is not a stored boolean: it is whether the client has a
-- resource server, which is why there is no column for it on `client`. Measured
-- 2026-08-31 on a live 26.7.1 and it is the reason this table has no `enabled`
-- column of its own:
--
--   * a client without the flag answers `404 {"error":"HTTP 404 Not Found"}` on
--     every path under `authz/resource-server`, and its representation omits
--     the key entirely rather than carrying `false`;
--   * `PUT /clients/{uuid}` with `"authorizationServicesEnabled":false` makes
--     the key vanish **and destroys the settings** - turning it on again
--     answered `allowRemoteResourceManagement:true`, `ENFORCING`, `UNANIMOUS`
--     after a `PUT` had set them to `false`, `PERMISSIVE`, `AFFIRMATIVE`.
--     A row that survived the flag would offer a state Keycloak cannot reach.
--
-- So a second truth is exactly what a boolean column here would create, and the
-- `ON DELETE CASCADE` plus the delete on the flag going off is the whole
-- lifecycle.
--
-- Three settable fields and no more. The `resources`, `policies` and `scopes`
-- arrays in the representation are **always empty on the resource-server read**
-- - measured with four scopes in the resource server - so they are not columns
-- and not a view over anything.
--
-- allow_remote_resource_management is INTEGER in both drivers, following
-- organization.enabled next door: the two migrations are byte-identical per
-- driver on purpose and a BOOLEAN here would be the first place they diverge.
--
-- policy_enforcement_mode and decision_strategy are TEXT rather than CHECK
-- constrained. An invalid value is refused above this layer with the measured
-- `400 {"error":"unknown_error","error_description":"Cannot parse the JSON"}`,
-- which is a parse failure although the JSON parses; a CHECK would answer a
-- constraint violation the handler would then have to translate back.
CREATE TABLE authz_resource_server (
    client_id                        TEXT PRIMARY KEY REFERENCES client (id) ON DELETE CASCADE,
    allow_remote_resource_management INTEGER NOT NULL,
    policy_enforcement_mode          TEXT NOT NULL,
    decision_strategy                TEXT NOT NULL
);

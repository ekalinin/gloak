-- A client's description.
--
-- Found 2026-08-23 by driving Gloak with kcadm.sh, the Keycloak image's own
-- admin CLI: `kcadm update clients/{id} -s description=...` answered 204 and
-- the value vanished. None of the six bootstrapped clients carries a
-- description, so no golden had ever covered the field.
--
-- Measured position: between name and rootUrl.
ALTER TABLE client ADD COLUMN description TEXT NOT NULL DEFAULT '';

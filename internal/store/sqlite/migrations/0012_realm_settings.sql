-- The rest of Keycloak's RealmRepresentation, as the JSON it arrived as.
--
-- Empty rather than NULL so the scan needs no sql.NullString: "never written"
-- and "written as nothing" are the same state here, and the admin layer falls
-- back to the measured defaults for the realm's name in both.
ALTER TABLE realm ADD COLUMN settings TEXT NOT NULL DEFAULT '';

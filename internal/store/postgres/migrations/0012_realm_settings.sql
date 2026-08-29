-- The rest of Keycloak's RealmRepresentation, as the JSON it arrived as.
--
-- TEXT rather than JSONB: the column is written and read whole and never
-- queried into, and JSONB would reorder its keys, which are the contract. The
-- SQLite driver stores the same string, so the two agree byte for byte.
--
-- Empty rather than NULL so the scan needs no null handling: "never written"
-- and "written as nothing" are the same state here, and the admin layer falls
-- back to the measured defaults for the realm's name in both.
ALTER TABLE realm ADD COLUMN settings TEXT NOT NULL DEFAULT '';

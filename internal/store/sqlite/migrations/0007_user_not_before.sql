-- The user's not-before instant, a Unix second.
--
-- Measured 2026-08-23: POST /admin/realms/{realm}/users/{id}/logout sets it to
-- the moment of the logout, and the user representation shows it. Without it
-- the representation reads 0 forever and the logout's only visible effect is
-- its status code.
ALTER TABLE user_entity ADD COLUMN not_before INTEGER NOT NULL DEFAULT 0;

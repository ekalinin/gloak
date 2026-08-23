-- A credential carries a user-facing label and a position in the user's list.
--
-- Both are observable: userLabel appears in the credential representation
-- between type and createdDate, and the moveAfter/moveToFirst endpoints exist
-- to reorder. Measured 2026-08-23.
--
-- UNIQUE (user_id, type) from 0001 stays. P2's plan expected to relax it so a
-- user could hold several credentials of one type, but reset-password was
-- measured *replacing* the password credential in place - same id, refreshed
-- createdDate, label cleared - and no admin API path creates a second one.
-- Relaxing it would model a state that cannot occur, and would put P1's
-- password lookup at risk for nothing.
ALTER TABLE credential ADD COLUMN user_label TEXT NOT NULL DEFAULT '';
ALTER TABLE credential ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;

-- A user's pending required actions. Measured: a reset-password carrying
-- temporary true adds UPDATE_PASSWORD, which the user representation shows.
ALTER TABLE user_entity ADD COLUMN required_actions TEXT NOT NULL DEFAULT '[]';

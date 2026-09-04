-- A realm's initial access tokens: bearer tokens that may register clients
-- through /realms/{realm}/clients-registrations/{provider}.
--
-- **The token is not a column.** Measured 2026-09-03 on a live 26.7.1: the
-- value is a JWT signed HS512 with the realm's HMAC key whose payload is
-- {exp, iat, jti, iss, aud, typ} with typ InitialAccessToken and jti equal to
-- this row's id. So the row is what the token points at rather than a copy of
-- it, which is the shape the registration access token already uses, and it is
-- also why `GET /clients-initial-access` can serve five keys where the create
-- serves six: there is nothing stored to serve the sixth from.
--
-- `expiration` is an interval in seconds and not an instant - `expiration: 600`
-- produces a token whose exp is iat + 600, and `expiration: 0` produces one
-- whose exp is the literal 0 - so it is stored as the caller sent it and the
-- arithmetic lives where the token is minted.
--
-- `total_count` and `remaining_count` are two columns because both are served
-- and they diverge: a registration decrements the second and leaves the first,
-- and an exhausted row stays in the listing at zero rather than being swept.
-- It may be zero, which is a 201 creating a token that can never be used; a
-- negative one is refused before it reaches here. The wire spells the two
-- `count` and `remainingCount`; the first is spelled out here because `count`
-- is a keyword Postgres reads in more than one way and a column name that
-- needs quoting in one driver and not the other is exactly the kind of
-- divergence the two-driver rule exists to prevent - `timestamp` likewise.
--
-- `ordinal` is what makes the listing insertion-ordered, which is measured:
-- three rows created in one realm came back in creation order on two container
-- starts and their ids are random UUIDs that do not sort that way. It is the
-- `component` table's device, for the same reason.
--
-- ON DELETE CASCADE removes a deleted realm's rows; bootstrap.DeleteRealm needs
-- no clause of its own.
CREATE TABLE client_initial_access (
    id                TEXT PRIMARY KEY,
    realm_id          TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    created_timestamp INTEGER NOT NULL,
    expiration        INTEGER NOT NULL,
    total_count       INTEGER NOT NULL,
    remaining_count   INTEGER NOT NULL,
    ordinal           INTEGER NOT NULL
);

CREATE INDEX idx_client_initial_access_realm ON client_initial_access (realm_id);

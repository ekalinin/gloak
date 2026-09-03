-- An organization's members, and the column that ties an identity provider to
-- an organization.
--
-- ## organization_member
--
-- **A member is a user and nothing else**, so the table is the pair and has no
-- id of its own. Measured 2026-09-02: `POST .../members` carrying a user id
-- answers 201 with a `Location` ending in **that same id**, the single read
-- addresses the user by it, and the representation's `id` is the user's. No
-- membership id is ever minted and none is ever served, so a surrogate key here
-- would be a value nothing on the wire could ever name.
--
-- There is no created date column. The representation carries
-- `createdTimestamp` and it is the **user's** - a user created long before it
-- joined reads back with its own creation time - so a per-membership date would
-- be a second truth nothing serves.
--
-- Both foreign keys cascade and both cascades are measured rather than tidy:
-- `DELETE /users/{id}` took the member out of the listing, and
-- `DELETE /organizations/{id}` emptied
-- `GET /organizations/members/{that user}/organizations`. The user's own row
-- survives the member delete - `DELETE .../members/{id}` is 204 and the user
-- still reads 200 - which is why the cascade points this way and not the other.
--
-- The composite primary key is the duplicate check. `POST .../members` twice is
-- `409 {"errorMessage":"User is already a member of the organization."}`, so the
-- driver has to be able to tell a repeat from a fresh insert, and a UNIQUE
-- constraint is what says so once instead of once per driver.
--
-- **membershipType is not a column.** Every member this project can create is
-- `UNMANAGED`, because `MANAGED` is what a user the organization itself
-- provisioned carries - through a completed invitation or an identity provider
-- link - and neither is reachable without a mail sender. Storing a constant
-- would look like state.
CREATE TABLE organization_member (
    organization_id TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES user_entity (id) ON DELETE CASCADE,
    PRIMARY KEY (organization_id, user_id)
);

CREATE INDEX organization_member_user ON organization_member (user_id);

-- ## identity_provider.organization_id
--
-- **The organization's identity providers are a column on the provider, not a
-- join table**, and that is measured from both sides.
-- `POST /organizations/{org}/identity-providers` with an alias answers 204 and
-- the **realm's own** read - `GET /identity-provider/instances/{alias}`, a
-- different route in a different chapter - starts carrying
-- `"organizationId":"{org}"`. `DELETE .../identity-providers/{alias}` drops the
-- key again and leaves the provider itself alone. A provider already associated
-- with another organization is refused
-- `400 {"errorMessage":"Identity provider already associated with a different
-- organization"}`, which is the same statement from the other direction: one
-- provider reaches at most one organization.
--
-- It is nullable rather than NOT NULL DEFAULT '' because absent is what every
-- provider on a default install is, and the representation omits the key
-- entirely then.
--
-- There is no REFERENCES organization (id) here, for organization_domain's
-- reason one migration back: the realm is not on this row's join path to the
-- organization, and adding it to get the constraint would put the realm in two
-- places that could disagree. The handler resolves the organization inside the
-- realm before it writes.
ALTER TABLE identity_provider ADD COLUMN organization_id TEXT;

-- The `Workflows` tag: a realm's workflows, their steps, and the steps an
-- activation has scheduled against one resource.
--
-- **The name is unique per realm and the id is not server-minted.** A create
-- naming `id: my-own-id` answered 201 with exactly that id in `Location`, and a
-- second create of an existing **name** answered 400
-- `Workflow name must be unique. A workflow with name 'n1' already exists.` So
-- the uniqueness Keycloak enforces is on (realm_id, name), and the id is the
-- primary key the caller may choose - which is what lets a conformance fixture
-- know a workflow's id before it asks for it, the same way the client-scope
-- fixtures do.
--
-- **Four columns the description's schema would suggest are deliberately
-- absent**, each because no request can put a value in it and no response has
-- ever carried one:
--
--   * `enabled` - a create carrying it is 400 `Cannot parse the JSON`;
--   * a step's `config` - the same 400, as a plain map and as the multivalued
--     map the schema declares;
--   * `with` - accepted at create and echoed by no read;
--   * `state` - never measured on the wire.
--
-- A column for any of them would be the claim F157 names: a table nothing
-- writes is a statement about the model that is not true.
--
-- `on_expression` and `if_expression` are spelled with a suffix because `on`
-- and `if` are SQL keywords in one dialect or the other, and a quoted column
-- name is a thing every query then has to remember.
--
-- `schedule_batch_size` is 0 for absent. `batch-size: 0` has not been measured,
-- and this is the one value the column cannot tell from an omission - said here
-- because the alternative, a nullable integer, would put the same decision in
-- two places for a case nobody has produced.
CREATE TABLE workflow (
    id                  TEXT NOT NULL PRIMARY KEY,
    realm_id            TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    on_expression       TEXT NOT NULL,
    if_expression       TEXT NOT NULL,
    schedule_after      TEXT NOT NULL,
    schedule_batch_size INTEGER NOT NULL,
    cancel_in_progress  TEXT NOT NULL,
    restart_in_progress TEXT NOT NULL,
    UNIQUE (realm_id, name)
);

-- `ordinal` exists because a workflow's steps come back in **insertion order**,
-- measured on a three-step workflow added disable-user, delete-user,
-- notify-user and served in exactly that order. Neither `uses`, `after` nor the
-- minted id reproduces it.
--
-- A step's id is server-minted whatever the request says: a create naming
-- `id:` inside a step got a different id back. That is the opposite of the
-- workflow's own id one table up, on one request body.
CREATE TABLE workflow_step (
    id          TEXT NOT NULL PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES workflow (id) ON DELETE CASCADE,
    uses        TEXT NOT NULL,
    after       TEXT NOT NULL,
    ordinal     INTEGER NOT NULL
);

CREATE INDEX idx_workflow_step_workflow ON workflow_step (workflow_id);

-- One row per scheduled step, which is what an activation writes.
--
-- **An activation schedules every step, not only the first.** Measured on a
-- three-step workflow with `after` of P1D, P2D and P3D: the three `scheduled-at`
-- values came back one, three and six days out, so each step's time is the
-- previous step's plus its own duration and the first is the activation instant
-- plus its own.
--
-- `resource_id` is not a foreign key and must not become one. The activation
-- route resolves the resource and refuses an unknown one with 400
-- `Resource with id <id> not found`, but the **read** beside it,
-- `GET /workflows/scheduled/{resource-id}`, answers 200 and `[]` for an id that
-- names nothing at all - so the read resolves nothing, and a REFERENCES clause
-- would make a delete of the user cascade a row this table is measured to keep
-- deciding for itself.
--
-- `scheduled_at` is epoch **milliseconds**, thirteen digits.
CREATE TABLE workflow_scheduled_step (
    workflow_id   TEXT NOT NULL REFERENCES workflow (id) ON DELETE CASCADE,
    step_id       TEXT NOT NULL REFERENCES workflow_step (id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    scheduled_at  INTEGER NOT NULL,
    status        TEXT NOT NULL,
    PRIMARY KEY (step_id, resource_type, resource_id)
);

CREATE INDEX idx_workflow_scheduled_resource ON workflow_scheduled_step (resource_id);

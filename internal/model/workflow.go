package model

// A workflow, its steps, and one step scheduled against one resource: the
// storage side of the `Workflows` tag.
//
// **Four fields the description declares are not here, and each is absent for
// its own measured reason.** Adding a column for one of them would be the claim
// F157 warns about - a table nothing writes is a statement about the model that
// is not true - so they are listed rather than modelled:
//
//   - `enabled` is refused by the deserialiser. A create carrying
//     `enabled: false` answers 400 `Cannot parse the JSON`, so no request can
//     put a value in it and no response has ever carried one.
//   - a step's `config` is refused the same way, both as a one-key map and as
//     the multivalued map the schema declares. It is unreachable on 26.7.1.
//   - `with` is accepted at create and **not echoed back** by any read, so
//     nothing observable depends on what was sent.
//   - `state` has never appeared in a measured body.
//
// Everything below did appear on the wire on 2026-09-06, container kc-wf.
type Workflow struct {
	ID      string
	RealmID string
	Name    string
	// On is the event expression, stored as the caller wrote it. Keycloak
	// parses it with an ANTLR grammar and reports a line and column on a
	// compound expression; Gloak validates a bare provider id and passes
	// anything else through - see internal/admin/workflows.go.
	On string
	// ScheduleAfter and ScheduleBatchSize are the `schedule` block, which is
	// emitted only when one of them is set. A batch size of zero reads as
	// absent; `batch-size: 0` has not been measured, and it is the one value
	// this pair cannot distinguish from an omission.
	ScheduleAfter     string
	ScheduleBatchSize int
	// CancelInProgress and RestartInProgress are the `concurrency` block, and
	// they are strings rather than booleans because Keycloak parses them as
	// expressions: `cancel-in-progress: "true"` is accepted and echoed, and
	// `restart-in-progress: "false"` is 400
	// `Could not find provider factory with id: false`.
	CancelInProgress  string
	RestartInProgress string
	// If is the condition expression, validated against the four measured
	// `workflow-condition` provider ids.
	If string
	// Steps is in insertion order, which is the order every measured body
	// serves them in.
	Steps []WorkflowStep
}

// WorkflowStep is one step of a workflow. The field order is the order the wire
// carries, which is the description's declaration order with the two scheduling
// fields between After and ID.
type WorkflowStep struct {
	ID    string
	Uses  string
	After string
}

// WorkflowScheduledStep is one step scheduled against one resource, which is
// what `POST .../activate/{type}/{resourceId}` writes and
// `GET /workflows/scheduled/{resource-id}` reads.
//
// **An activation schedules every step, not only the first**, and the times are
// cumulative: the first step is the activation instant plus its own `after`,
// and each later step is the previous step's time plus its own. Measured on a
// three-step workflow with P1D, P2D and P3D, whose three `scheduled-at` values
// came back exactly one, three and six days out.
type WorkflowScheduledStep struct {
	WorkflowID string
	StepID     string
	// ResourceType is `USERS` or `CLIENTS`, upper case. The path segment is an
	// enum: `users` in lower case does not route at all.
	ResourceType string
	ResourceID   string
	// ScheduledAt is epoch **milliseconds**, thirteen digits.
	ScheduledAt int64
	// Status is `PENDING` on everything measured. `COMPLETED` is the other
	// constant the description declares and nothing here can reach it,
	// because nothing here runs a step.
	Status string
}

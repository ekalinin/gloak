package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The `Workflows` tag, all nine of its operations.
//
// **The entry that asked for this said "nine operations answering
// `application/yaml`". Two of them do.** Counted from the responses on
// 2026-09-06 rather than from the description's content lists, which name the
// media type on request bodies as well:
//
//	GET  /workflows                      application/yaml;charset=UTF-8, chunked
//	GET  /workflows/{id}                 application/yaml;charset=UTF-8, chunked
//	GET  /workflows/scheduled/{id}       application/json;charset=UTF-8 - and 406
//	                                     for Accept: application/yaml
//	POST /workflows                      201, empty, no Content-Type
//	PUT, DELETE, migrate, activate,
//	deactivate                           204
//
// The two YAML reads are content-negotiated and YAML is the server's preference:
// `application/json` alone or at a higher q gets JSON, and everything else -
// including an absent header, `*/*`, `text/html` and `text/plain` - gets YAML.
//
// **The bytes are written by internal/httpx and read by a library.** That split
// is the decision this chapter is really about. A response body is observable,
// so its emitter is bespoke - see internal/httpx/yaml.go for the four ways
// gopkg.in/yaml.v3 differs from Keycloak's bytes. A request body is not
// observable at all, so the reader is the library, which also accepts every
// spelling SnakeYAML accepts and a hand-written subset parser would refuse.
// YAML is a superset of JSON, so one decoder serves both of the media types
// these routes consume.
//
// **The guard is a shape this project has not met before: the realm role
// `admin` itself.** Every one of the twenty-one `master-realm` admin roles is
// 403 on every one of the nine, held singly; so are view-realm+view-users,
// manage-realm+manage-users, six held together, and all twenty-one plus
// create-realm - which is exactly `admin`'s composite closure. Holding `admin`
// is 200/201/204 and removing it again is 403 again, with GET /users and
// GET /admin/realms as controls that flipped with the assignment in every row.
// So the check is on the role by name and not on what it confers, and an
// implementation that expanded composites would open the tag to a caller
// Keycloak refuses.
//
// **What is not built.** The `on` and `if` expressions are validated as bare
// provider ids against the measured SPI lists and stored as written; Keycloak
// parses them with an ANTLR grammar and reports a line and column on a compound
// one, so a request carrying an expression rather than an id gets a different
// error body here. Nothing schedules, runs or migrates a step: `activate`
// writes the rows `scheduled/{resource-id}` reads, and `migrate` validates its
// two step ids and answers 204. The observable is the answer.

// workflowRoles is what all nine operations accept, and it has one entry.
//
// It is the **realm role** `admin`, which resolveCaller already puts in
// adminGrants by name when the caller authenticated in master - see
// adminRoleNames. Every other guard in this file names roles of the admin
// container; this one names the composite that is over them, and the two are
// not interchangeable, measured in both directions.
var workflowRoles = []string{"admin"}

// The workflow-event and workflow-condition provider ids a default 26.7.1
// carries, read out of `GET /admin/serverinfo`'s provider list on 2026-09-06
// rather than guessed. An `on` or `if` naming something outside them is
// `Could not find provider factory with id: <name>`.
var (
	workflowEventProviders = map[string]bool{
		"client-authenticated": true, "client-created": true,
		"user-authenticated": true, "user-created": true,
		"user-federated-identity-added": true, "user-federated-identity-removed": true,
		"user-group-membership-added": true, "user-group-membership-removed": true,
		"user-role-granted": true, "user-role-revoked": true,
	}
	workflowConditionProviders = map[string]bool{
		"has-identity-provider-link": true, "has-role": true,
		"has-user-attribute": true, "is-member-of": true,
	}
)

// The workflow-step provider ids, and the resource type each one acts on.
//
// The type is what makes a workflow's steps compatible or not: a workflow
// mixing a user step with a client step is 400
// `Steps provided are not compatible with each other.`, and a workflow with
// **no** steps is 400
// `Steps provided should support a single type, actual: USERS, CLIENTS` -
// which is the same check reporting the whole set because nothing narrowed it.
var workflowStepProviders = map[string]string{
	"add-required-action":    workflowResourceUsers,
	"delete-user":            workflowResourceUsers,
	"disable-user":           workflowResourceUsers,
	"grant-role":             workflowResourceUsers,
	"join-group":             workflowResourceUsers,
	"leave-group":            workflowResourceUsers,
	"notify-user":            workflowResourceUsers,
	"remove-required-action": workflowResourceUsers,
	"remove-user-attribute":  workflowResourceUsers,
	"restart":                workflowResourceUsers,
	"revoke-role":            workflowResourceUsers,
	"set-user-attribute":     workflowResourceUsers,
	"unlink-user":            workflowResourceUsers,
	"delete-client":          workflowResourceClients,
	"disable-client":         workflowResourceClients,
}

// The two values the `{type}` path segment takes, upper case.
//
// **They are an enum and the segment is not free text.** `USERS` and `CLIENTS`
// reach the handler; `users`, `user`, `clients`, `client`, `User`, `groups`,
// `roles` and `organizations` all answer `{"error":"HTTP 404 Not Found"}` -
// which makes an unconvertible **path** parameter another producer of that
// body, beside the wrong method, the switched-off resource and the malformed
// integer query parameter AGENTS.md already lists.
const (
	workflowResourceUsers   = "USERS"
	workflowResourceClients = "CLIENTS"
)

// workflowRepresentation is the wire shape, in the measured key order - which
// is the description's declaration order with the absent keys skipped.
//
// Every field is omitempty because every one of them is measured **absent**
// rather than empty when it has no value: a workflow created with no `on`
// answers a body with no `on` key at all, and `includeId=false` removes `id`
// from the workflow and from each of its steps.
type workflowRepresentation struct {
	ID          string                             `json:"id,omitempty" yaml:"id,omitempty"`
	Name        string                             `json:"name,omitempty" yaml:"name,omitempty"`
	On          string                             `json:"on,omitempty" yaml:"on,omitempty"`
	Schedule    *workflowScheduleRepresentation    `json:"schedule,omitempty" yaml:"schedule,omitempty"`
	Concurrency *workflowConcurrencyRepresentation `json:"concurrency,omitempty" yaml:"concurrency,omitempty"`
	If          string                             `json:"if,omitempty" yaml:"if,omitempty"`
	Steps       []workflowStepRepresentation       `json:"steps,omitempty" yaml:"steps,omitempty"`
}

type workflowScheduleRepresentation struct {
	After     string `json:"after,omitempty" yaml:"after,omitempty"`
	BatchSize int    `json:"batch-size,omitempty" yaml:"batch-size,omitempty"`
}

type workflowConcurrencyRepresentation struct {
	CancelInProgress  string `json:"cancel-in-progress,omitempty" yaml:"cancel-in-progress,omitempty"`
	RestartInProgress string `json:"restart-in-progress,omitempty" yaml:"restart-in-progress,omitempty"`
}

// workflowStepRepresentation carries the two scheduling fields between `after`
// and `id`, which is where the wire puts them: they appear only on
// `GET /workflows/scheduled/{resource-id}` and never on the two reads.
type workflowStepRepresentation struct {
	Uses        string `json:"uses,omitempty" yaml:"uses,omitempty"`
	After       string `json:"after,omitempty" yaml:"after,omitempty"`
	ScheduledAt int64  `json:"scheduled-at,omitempty" yaml:"scheduled-at,omitempty"`
	Status      string `json:"status,omitempty" yaml:"status,omitempty"`
	ID          string `json:"id,omitempty" yaml:"id,omitempty"`
}

// listWorkflows serves GET /admin/realms/{realm}/workflows.
//
// The filters are the listing's own and are not any other listing's:
// `search` is a **case-insensitive substring**, `exact=true` turns it into
// equality, and **either bound alone pages** - which is neither the role
// listings' rule (search, or both bounds) nor the user listing's. A malformed
// bound is `{"error":"HTTP 404 Not Found"}`, the producer AGENTS.md records.
func (h *handler) listWorkflows(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	all, err := h.store.Workflows().List(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	search := r.URL.Query().Get("search")
	exact := r.URL.Query().Get("exact") == "true"
	matched := make([]*model.Workflow, 0, len(all))
	for _, wf := range all {
		if !workflowMatches(wf.Name, search, exact) {
			continue
		}
		matched = append(matched, wf)
	}

	first, ok := workflowBound(w, r, "first")
	if !ok {
		return
	}
	max, ok := workflowBound(w, r, "max")
	if !ok {
		return
	}
	matched = pageWorkflows(matched, first, max)

	out := make([]workflowRepresentation, 0, len(matched))
	for _, wf := range matched {
		out = append(out, workflowRepresentationOf(wf, true, nil))
	}
	writeWorkflowList(w, r, out)
}

// workflowMatches is the listing's filter. An empty search matches everything,
// including under exact=true - `exact=true&search=t` matched nothing where
// `exact=true&search=t2` matched the workflow named t2, so exact compares the
// whole name rather than opening a different index.
func workflowMatches(name, search string, exact bool) bool {
	if search == "" {
		return true
	}
	if exact {
		return name == search
	}
	return strings.Contains(strings.ToLower(name), strings.ToLower(search))
}

// workflowBound reads `first` or `max`. An absent bound is -1, meaning "no
// bound"; a bound that is not an integer is the router's own 404 body, which is
// what a live 26.7.1 answers `?max=abc`.
func workflowBound(w http.ResponseWriter, r *http.Request, name string) (int, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return -1, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
		return 0, false
	}
	return n, true
}

// pageWorkflows applies whichever bounds were given. **Either one alone pages**
// - `?max=1` returned the first of two and `?first=1` the second - which is
// this listing's own rule and the third one in this API.
func pageWorkflows(in []*model.Workflow, first, max int) []*model.Workflow {
	if first > 0 {
		if first >= len(in) {
			return nil
		}
		in = in[first:]
	}
	if max >= 0 && max < len(in) {
		in = in[:max]
	}
	return in
}

// readWorkflow serves GET /admin/realms/{realm}/workflows/{id}.
//
// `includeId=false` drops `id` from the workflow **and from every step**, which
// is what makes a golden of this route hold no server-minted value at all.
func (h *handler) readWorkflow(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	wf, ok := h.workflowFromPath(w, r, rc)
	if !ok {
		return
	}
	includeID := r.URL.Query().Get("includeId") != "false"
	writeWorkflowSingle(w, r, workflowRepresentationOf(wf, includeID, nil))
}

// createWorkflow serves POST /admin/realms/{realm}/workflows.
//
// **The body's `id` wins**, and it need not be a UUID: a create naming
// `id: my-own-id` answered 201 with that id in `Location`. That is
// `POST /clients`' rule on a third endpoint, and it is what lets a conformance
// fixture know a workflow's id before it asks for it. A **step's** id in the
// same body is measured to be ignored and replaced.
//
// The 201 carries no body and no `Content-Type`.
func (h *handler) createWorkflow(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	rep, ok := decodeWorkflowBody(w, r)
	if !ok {
		return
	}
	wf, ok := h.validateWorkflow(w, r, rc, rep, "")
	if !ok {
		return
	}
	if err := h.store.Workflows().Create(r.Context(), wf); err != nil {
		// **A duplicate id is not the duplicate name beside it.** The name
		// check above is `Workflow name must be unique. …`, measured
		// identically three times; a repeated **id** answers
		// `Duplicate resource error` in **two shapes** - 400 with
		// `errorMessage` and 409 with the RFC 6749 body - alternating on one
		// container within seconds, with the same body and the same caller.
		// Nothing in the request decides which, so no golden can hold it. The
		// 400 is served here because it is the one measured in isolation with
		// its headers read off the wire; the 409 is recorded in
		// docs/superpowers/handover/f121-workflows.md as unexplained rather
		// than implemented as a rule.
		if errors.Is(err, store.ErrConflict) {
			httpx.WriteAdminError(w, http.StatusBadRequest, "Duplicate resource error")
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Location",
		h.issuerBase+"/admin/realms/"+rc.realm.Name+"/workflows/"+wf.ID)
	httpx.WriteEmptyStatus(w, r, http.StatusCreated)
}

// updateWorkflow serves PUT /admin/realms/{realm}/workflows/{id}.
//
// It replaces rather than merges, steps included: a PUT re-measured on a live
// 26.7.1 came back with a step id the workflow did not have before, so the step
// list is rewritten and re-minted rather than reconciled.
func (h *handler) updateWorkflow(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	existing, ok := h.workflowFromPath(w, r, rc)
	if !ok {
		return
	}
	rep, ok := decodeWorkflowBody(w, r)
	if !ok {
		return
	}
	wf, ok := h.validateWorkflow(w, r, rc, rep, existing.ID)
	if !ok {
		return
	}
	wf.ID = existing.ID
	if err := h.store.Workflows().Update(r.Context(), wf); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// deleteWorkflow serves DELETE /admin/realms/{realm}/workflows/{id}.
//
// **A second delete of the same id is 400, not 204.** Almost every other delete
// in this API is idempotent; this one answers
// `Not a valid workflow resource: <id>` for an id it has already removed, which
// is why the resolution runs first rather than the delete swallowing a missing
// row.
func (h *handler) deleteWorkflow(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	wf, ok := h.workflowFromPath(w, r, rc)
	if !ok {
		return
	}
	if err := h.store.Workflows().Delete(r.Context(), rc.realm.ID, wf.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// migrateWorkflowSteps serves POST /admin/realms/{realm}/workflows/migrate.
//
// `from` and `to` are **step** ids, not workflow ids and not provider names: a
// `from=disable-user` answered `Not a valid workflow resource: disable-user`,
// and two real step ids answered 204. Either parameter alone is 400 with the
// message below, and both absent is the same message - so the check is on the
// pair rather than per parameter.
//
// Nothing is moved. What a migration does to a scheduled step was not measured
// and cannot be: the two ids that answered 204 named a step nothing had
// scheduled.
func (h *handler) migrateWorkflowSteps(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	if from == "" || to == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest,
			"Both 'from' and 'to' step ids must be provided for migration.")
		return
	}
	for _, id := range []string{from, to} {
		_, err := h.store.Workflows().StepByID(r.Context(), rc.realm.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			writeNotAValidWorkflowResource(w, id)
			return
		}
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	httpx.WriteNoContent(w, r)
}

// activateWorkflow serves
// POST /admin/realms/{realm}/workflows/{id}/activate/{type}/{resourceId}.
//
// **An activation schedules every step, and the times are cumulative.**
// Measured on a three-step workflow whose `after` values were P1D, P2D and P3D:
// the three `scheduled-at` values came back one, three and six days out, so
// each step's time is the previous step's plus its own duration and the first
// is the activation instant plus its own.
//
// `notBefore` is accepted and answered 204 and changes nothing observable here:
// what it moves was not measured, because the only window onto a schedule is
// `scheduled/{resource-id}` and the value it showed was the same either way.
//
// A repeat is 204 and leaves one row per step, which is why the store replaces
// rather than appends.
func (h *handler) activateWorkflow(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	wf, resourceType, resourceID, ok := h.workflowActivationTarget(w, r, rc)
	if !ok {
		return
	}
	at := time.Now().UnixMilli()
	rows := make([]model.WorkflowScheduledStep, 0, len(wf.Steps))
	for _, s := range wf.Steps {
		at += workflowDurationMillis(s.After)
		rows = append(rows, model.WorkflowScheduledStep{
			WorkflowID: wf.ID, StepID: s.ID,
			ResourceType: resourceType, ResourceID: resourceID,
			ScheduledAt: at, Status: "PENDING",
		})
	}
	if err := h.store.Workflows().Schedule(r.Context(), rc.realm.ID, rows); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// deactivateWorkflow serves the sibling POST. Deactivating a resource that was
// never activated is 204, measured before any activate had run.
func (h *handler) deactivateWorkflow(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	wf, resourceType, resourceID, ok := h.workflowActivationTarget(w, r, rc)
	if !ok {
		return
	}
	if err := h.store.Workflows().Unschedule(r.Context(), rc.realm.ID, wf.ID,
		resourceType, resourceID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// workflowActivationTarget resolves the three things both activation routes
// need, **in the measured order**: the workflow, then the type, then the
// resource.
//
// The order is not a preference. `POST /workflows/does-not-exist/activate/users/abc`
// - an unknown workflow and a type that does not route - answers about the
// workflow with a 400, while the same lower-case `users` on a workflow that
// exists answers the router's 404. So the workflow is resolved first even
// though the type is the segment a router would reject.
func (h *handler) workflowActivationTarget(w http.ResponseWriter, r *http.Request,
	rc *reqContext) (*model.Workflow, string, string, bool) {
	wf, ok := h.workflowFromPath(w, r, rc)
	if !ok {
		return nil, "", "", false
	}
	resourceType := r.PathValue("resourceType")
	if resourceType != workflowResourceUsers && resourceType != workflowResourceClients {
		httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
		return nil, "", "", false
	}
	resourceID := r.PathValue("resourceID")
	if !h.workflowResourceExists(r, rc, resourceType, resourceID) {
		httpx.WriteMessageError(w, http.StatusBadRequest,
			"Resource with id "+resourceID+" not found")
		return nil, "", "", false
	}
	return wf, resourceType, resourceID, true
}

// workflowResourceExists resolves the {resourceId} against the store the
// {type} names. An id naming nothing is 400 `Resource with id <id> not found`,
// measured on both a well-formed UUID and a bare word.
func (h *handler) workflowResourceExists(r *http.Request, rc *reqContext,
	resourceType, resourceID string) bool {
	if resourceType == workflowResourceClients {
		_, err := h.store.Clients().ByID(r.Context(), rc.realm.ID, resourceID)
		return err == nil
	}
	_, err := h.store.Users().ByID(r.Context(), rc.realm.ID, resourceID)
	return err == nil
}

// listScheduledWorkflows serves
// GET /admin/realms/{realm}/workflows/scheduled/{resource-id}.
//
// **It is the one read on this tag that is JSON only**, and it answers
// `Accept: application/yaml` with 406 and `{"error":"HTTP 406 Not Acceptable"}`
// - a sixth body in the fallback family, which AGENTS.md records as five.
//
// It resolves nothing: an id that names no user and no client answers 200 and
// `[]` rather than a 404, so there is no lookup here and the filter is on the
// id alone.
func (h *handler) listScheduledWorkflows(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if !workflowAcceptsJSON(r) {
		httpx.WriteMessageError(w, http.StatusNotAcceptable, "HTTP 406 Not Acceptable")
		return
	}
	resourceID := r.PathValue("resourceID")
	rows, err := h.store.Workflows().ScheduledFor(r.Context(), rc.realm.ID, resourceID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	scheduled := make(map[string]model.WorkflowScheduledStep, len(rows))
	order := make([]string, 0, len(rows))
	for _, row := range rows {
		if _, seen := scheduled[row.WorkflowID]; !seen {
			order = append(order, row.WorkflowID)
		}
		scheduled[row.StepID] = row
	}

	out := make([]workflowRepresentation, 0, len(order))
	all, err := h.store.Workflows().List(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	for _, wf := range all {
		if !workflowIsScheduled(wf, scheduled) {
			continue
		}
		out = append(out, workflowRepresentationOf(wf, true, scheduled))
	}
	httpx.WriteJSONCharset(w, http.StatusOK, out)
}

func workflowIsScheduled(wf *model.Workflow, scheduled map[string]model.WorkflowScheduledStep) bool {
	for _, s := range wf.Steps {
		if _, ok := scheduled[s.ID]; ok {
			return true
		}
	}
	return false
}

// workflowFromPath resolves {id} inside the caller's realm.
//
// **An id that resolves to nothing is 400, not 404**, and the message
// interpolates the request's own value. It is deliberately not on AGENTS.md's
// list of not-found spellings for the reason that list gives about
// `Requested audience not available`: a sentence carrying the caller's value is
// a template rather than a spelling. A workflow of another realm answers it
// too, so the realm is part of the lookup and not a later check.
func (h *handler) workflowFromPath(w http.ResponseWriter, r *http.Request,
	rc *reqContext) (*model.Workflow, bool) {
	id := r.PathValue("workflowID")
	wf, err := h.store.Workflows().ByID(r.Context(), rc.realm.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeNotAValidWorkflowResource(w, id)
		return nil, false
	}
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return wf, true
}

func writeNotAValidWorkflowResource(w http.ResponseWriter, id string) {
	httpx.WriteMessageError(w, http.StatusBadRequest, "Not a valid workflow resource: "+id)
}

// validateWorkflow turns a decoded body into a storable workflow, running the
// checks in the order the measured messages put them.
//
// Measured on a live 26.7.1, one fault at a time:
//
//	name absent or ""      Workflow name cannot be null or empty.
//	name already taken     Workflow name must be unique. A workflow with name 'n1' already exists.
//	on names no provider   Could not find provider factory with id: <name>
//	if names no provider   Could not find provider factory with id: <name>
//	uses names no step      Could not find step provider: <name>
//	after not a duration   Step 'after' configuration is not valid: 5 days
//	no steps at all        Steps provided should support a single type, actual: USERS, CLIENTS
//	steps of two types     Steps provided are not compatible with each other.
//
// existingID is empty on a create and the workflow's own id on an update, so
// renaming a workflow to the name it already has is not a conflict with itself.
func (h *handler) validateWorkflow(w http.ResponseWriter, r *http.Request, rc *reqContext,
	rep workflowRepresentation, existingID string) (*model.Workflow, bool) {
	if strings.TrimSpace(rep.Name) == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Workflow name cannot be null or empty.")
		return nil, false
	}
	clash, err := h.store.Workflows().ByName(r.Context(), rc.realm.ID, rep.Name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	if clash != nil && clash.ID != existingID {
		httpx.WriteAdminError(w, http.StatusBadRequest,
			"Workflow name must be unique. A workflow with name '"+rep.Name+"' already exists.")
		return nil, false
	}
	// An absent `on` is a 201: a workflow with no event is legal and comes
	// back with no `on` key at all.
	if rep.On != "" && !workflowEventProviders[rep.On] {
		httpx.WriteAdminError(w, http.StatusBadRequest,
			"Could not find provider factory with id: "+rep.On)
		return nil, false
	}
	if rep.If != "" && !workflowConditionProviders[rep.If] {
		httpx.WriteAdminError(w, http.StatusBadRequest,
			"Could not find provider factory with id: "+rep.If)
		return nil, false
	}

	types := map[string]bool{}
	steps := make([]model.WorkflowStep, 0, len(rep.Steps))
	for _, s := range rep.Steps {
		kind, known := workflowStepProviders[s.Uses]
		if !known {
			httpx.WriteAdminError(w, http.StatusBadRequest,
				"Could not find step provider: "+s.Uses)
			return nil, false
		}
		if s.After != "" && workflowDurationMillis(s.After) < 0 {
			httpx.WriteAdminError(w, http.StatusBadRequest,
				"Step 'after' configuration is not valid: "+s.After)
			return nil, false
		}
		types[kind] = true
		// The step's id is minted here whatever the body said, measured.
		steps = append(steps, model.WorkflowStep{
			ID: model.NewID(), Uses: s.Uses, After: s.After,
		})
	}
	switch len(types) {
	case 1:
	case 0:
		httpx.WriteAdminError(w, http.StatusBadRequest,
			"Steps provided should support a single type, actual: "+
				workflowResourceUsers+", "+workflowResourceClients)
		return nil, false
	default:
		httpx.WriteAdminError(w, http.StatusBadRequest,
			"Steps provided are not compatible with each other.")
		return nil, false
	}

	wf := &model.Workflow{
		ID: rep.ID, RealmID: rc.realm.ID, Name: rep.Name, On: rep.On, If: rep.If,
		Steps: steps,
	}
	if wf.ID == "" {
		wf.ID = model.NewID()
	}
	if rep.Schedule != nil {
		wf.ScheduleAfter, wf.ScheduleBatchSize = rep.Schedule.After, rep.Schedule.BatchSize
	}
	if rep.Concurrency != nil {
		wf.CancelInProgress = rep.Concurrency.CancelInProgress
		wf.RestartInProgress = rep.Concurrency.RestartInProgress
	}
	return wf, true
}

// workflowDurationMillis parses the ISO-8601 duration a step's `after` carries,
// returning -1 for anything it is not.
//
// **`after` is an ISO-8601 duration and nothing else.** `P5D` is a 201;
// `5 days`, `5d`, `5 day`, `5`, `5000`, `5 DAYS` and `5days` are all 400
// `Step 'after' configuration is not valid: <value>`. `PT5M` is refused too, so
// the accepted shape is the date part alone rather than the whole grammar -
// measured, and the reason this is a hand parser rather than a call to
// time.ParseDuration, which accepts none of these spellings and would accept
// `5m`, which Keycloak does not.
func workflowDurationMillis(after string) int64 {
	if !strings.HasPrefix(after, "P") || strings.Contains(after, "T") {
		return -1
	}
	const day = int64(24 * 60 * 60 * 1000)
	var total, digits int64
	seen := false
	for _, c := range after[1:] {
		switch {
		case c >= '0' && c <= '9':
			digits = digits*10 + int64(c-'0')
			seen = true
		case c == 'D' && seen:
			total += digits * day
			digits, seen = 0, false
		case c == 'W' && seen:
			total += digits * 7 * day
			digits, seen = 0, false
		default:
			return -1
		}
	}
	if seen || total == 0 {
		return -1
	}
	return total
}

// decodeWorkflowBody reads a request body that may be YAML or JSON.
//
// One decoder for both, because YAML is a superset of JSON and both media types
// arrive on the same two routes. `KnownFields` is on, which is what refuses the
// two schema fields 26.7.1's own deserialiser refuses: a body carrying
// `enabled` or a step's `config` is 400 `unknown_error`/`Cannot parse the JSON`,
// measured on both.
//
// The three failures are measured and are three different answers:
//
//	empty body        500 {"error":"unknown_error","error_description":
//	                       "For more on this error consult the server log."}
//	an unknown field  400 unknown_error       Cannot parse the JSON
//	a syntax error    400 invalid_request     Cannot parse the JSON
//
// The empty-body 500 is Keycloak's own defect, the same family as an empty body
// on `POST /users`, and it is reproduced rather than tidied.
func decodeWorkflowBody(w http.ResponseWriter, r *http.Request) (workflowRepresentation, bool) {
	var rep workflowRepresentation
	body, err := readRequestBody(r)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return rep, false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
			"For more on this error consult the server log.")
		return rep, false
	}
	dec := yaml.NewDecoder(strings.NewReader(string(body)))
	dec.KnownFields(true)
	if err := dec.Decode(&rep); err != nil {
		code := "invalid_request"
		if strings.Contains(err.Error(), "not found in type") {
			code = "unknown_error"
		}
		httpx.WriteOAuthError(w, http.StatusBadRequest, code, "Cannot parse the JSON")
		return rep, false
	}
	return rep, true
}

// workflowRepresentationOf projects a stored workflow onto the wire.
//
// includeID is `includeId`'s value, which removes the id from the workflow and
// from every step. scheduled is nil on the two reads and carries the rows on
// `scheduled/{resource-id}`, where a step gains `scheduled-at` and `status`
// between its `after` and its `id`.
func workflowRepresentationOf(wf *model.Workflow, includeID bool,
	scheduled map[string]model.WorkflowScheduledStep) workflowRepresentation {
	rep := workflowRepresentation{Name: wf.Name, On: wf.On, If: wf.If}
	if includeID {
		rep.ID = wf.ID
	}
	if wf.ScheduleAfter != "" || wf.ScheduleBatchSize != 0 {
		rep.Schedule = &workflowScheduleRepresentation{
			After: wf.ScheduleAfter, BatchSize: wf.ScheduleBatchSize,
		}
	}
	if wf.CancelInProgress != "" || wf.RestartInProgress != "" {
		rep.Concurrency = &workflowConcurrencyRepresentation{
			CancelInProgress: wf.CancelInProgress, RestartInProgress: wf.RestartInProgress,
		}
	}
	for _, s := range wf.Steps {
		step := workflowStepRepresentation{Uses: s.Uses, After: s.After}
		if row, ok := scheduled[s.ID]; ok {
			step.ScheduledAt, step.Status = row.ScheduledAt, row.Status
		}
		if includeID {
			step.ID = s.ID
		}
		rep.Steps = append(rep.Steps, step)
	}
	return rep
}

// workflowYAML builds the ordered mapping internal/httpx emits, in the same
// order the struct above declares.
//
// It is written out rather than derived by reflection so that the YAML order
// and the JSON order are two statements of one measurement that a reader can
// compare, which is what a reflective walk over the json tags would hide.
func workflowYAML(rep workflowRepresentation) httpx.YAMLMap {
	m := httpx.YAMLMap{}
	add := func(key, value string) {
		if value != "" {
			m = append(m, httpx.YAMLPair{Key: key, Value: value})
		}
	}
	add("id", rep.ID)
	add("name", rep.Name)
	add("on", rep.On)
	if rep.Schedule != nil {
		s := httpx.YAMLMap{}
		if rep.Schedule.After != "" {
			s = append(s, httpx.YAMLPair{Key: "after", Value: rep.Schedule.After})
		}
		if rep.Schedule.BatchSize != 0 {
			s = append(s, httpx.YAMLPair{Key: "batch-size", Value: rep.Schedule.BatchSize})
		}
		m = append(m, httpx.YAMLPair{Key: "schedule", Value: s})
	}
	if rep.Concurrency != nil {
		c := httpx.YAMLMap{}
		if rep.Concurrency.CancelInProgress != "" {
			c = append(c, httpx.YAMLPair{
				Key: "cancel-in-progress", Value: rep.Concurrency.CancelInProgress})
		}
		if rep.Concurrency.RestartInProgress != "" {
			c = append(c, httpx.YAMLPair{
				Key: "restart-in-progress", Value: rep.Concurrency.RestartInProgress})
		}
		m = append(m, httpx.YAMLPair{Key: "concurrency", Value: c})
	}
	add("if", rep.If)
	if len(rep.Steps) > 0 {
		steps := make([]httpx.YAMLMap, 0, len(rep.Steps))
		for _, s := range rep.Steps {
			step := httpx.YAMLMap{}
			if s.Uses != "" {
				step = append(step, httpx.YAMLPair{Key: "uses", Value: s.Uses})
			}
			if s.After != "" {
				step = append(step, httpx.YAMLPair{Key: "after", Value: s.After})
			}
			if s.ScheduledAt != 0 {
				step = append(step, httpx.YAMLPair{Key: "scheduled-at", Value: s.ScheduledAt})
			}
			if s.Status != "" {
				step = append(step, httpx.YAMLPair{Key: "status", Value: s.Status})
			}
			if s.ID != "" {
				step = append(step, httpx.YAMLPair{Key: "id", Value: s.ID})
			}
			steps = append(steps, step)
		}
		m = append(m, httpx.YAMLPair{Key: "steps", Value: steps})
	}
	return m
}

// writeWorkflowList and writeWorkflowSingle are the two content-negotiated
// reads. See workflowPrefersJSON for how the choice is made.
func writeWorkflowList(w http.ResponseWriter, r *http.Request, out []workflowRepresentation) {
	if workflowPrefersJSON(r) {
		httpx.WriteJSONCharset(w, http.StatusOK, out)
		return
	}
	body := make([]httpx.YAMLMap, 0, len(out))
	for _, rep := range out {
		body = append(body, workflowYAML(rep))
	}
	httpx.WriteYAML(w, http.StatusOK, body)
}

func writeWorkflowSingle(w http.ResponseWriter, r *http.Request, rep workflowRepresentation) {
	if workflowPrefersJSON(r) {
		httpx.WriteJSONCharset(w, http.StatusOK, rep)
		return
	}
	httpx.WriteYAML(w, http.StatusOK, workflowYAML(rep))
}

// workflowPrefersJSON decides which of the two representations a read serves.
//
// **YAML is the default and JSON has to outrank it**, measured over seven
// Accept headers on one route:
//
//	(absent)                                    yaml
//	*/*                                         yaml
//	text/html                                   yaml
//	text/plain                                  yaml
//	application/json, application/yaml          yaml
//	application/json                            json
//	application/yaml;q=0.5, application/json    json
//
// The fifth row is what says a tie goes to YAML rather than to the order the
// header lists, and the third and fourth say a header matching neither is not a
// 406 on these two routes. So the rule is `q(json) > q(yaml)`, with an absent
// or unmatched header leaving both at the same value.
func workflowPrefersJSON(r *http.Request) bool {
	return acceptQuality(r, "application/json") > acceptQuality(r, "application/yaml")
}

// workflowAcceptsJSON is `scheduled/{resource-id}`'s 406 check: that route
// serves JSON alone, and `Accept: application/yaml` is
// `{"error":"HTTP 406 Not Acceptable"}`.
func workflowAcceptsJSON(r *http.Request) bool {
	return acceptQuality(r, "application/json") > 0
}

// acceptQuality is the q value an Accept header gives one media type, taking
// `application/*` and `*/*` into account. An absent header is 1, which is what
// makes it behave as `*/*` - measured, since a request with no Accept and one
// with `*/*` got the same answer on every route here.
func acceptQuality(r *http.Request, mediaType string) float64 {
	header := strings.TrimSpace(r.Header.Get("Accept"))
	if header == "" {
		return 1
	}
	kind, _, _ := strings.Cut(mediaType, "/")
	best := 0.0
	for _, part := range strings.Split(header, ",") {
		spelling, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		spelling = strings.ToLower(strings.TrimSpace(spelling))
		if spelling != mediaType && spelling != kind+"/*" && spelling != "*/*" {
			continue
		}
		q := 1.0
		for _, p := range strings.Split(params, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(p), "=")
			if !ok || strings.TrimSpace(name) != "q" {
				continue
			}
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
				q = parsed
			}
		}
		if q > best {
			best = q
		}
	}
	return best
}

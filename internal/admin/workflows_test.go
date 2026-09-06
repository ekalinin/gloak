package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

const workflowBase = "/admin/realms/master/workflows"

// sendTyped is the localization family's helper, reused here: this chapter
// needs the request's Content-Type spelled out for the same kind of reason,
// since `application/yaml` is what its writes send and it is the value that
// decides X-Frame-Options.

const minimalWorkflow = "name: gloak-probe-wf\non: user-created\n" +
	"steps:\n  - uses: disable-user\n    after: P5D\n"

// TestWorkflowGuardIsTheAdminRoleItselfAndNotItsComposites is the finding this
// chapter's guard rests on, and no golden can state it.
//
// A conformance case can show that one caller is refused. What it cannot show
// is that the refusal survives **every** admin role held together, which is the
// part that separates "checks a role by name" from "checks what the caller can
// do". Measured on a live 26.7.1 in exactly this shape: all twenty-one
// master-realm roles plus create-realm - `admin`'s whole composite closure -
// are 403 on all nine routes, and `admin` itself is 200.
//
// The control is in the same test: the same caller reads GET /users, so a run
// where the role assignment silently did nothing fails here rather than passing
// as a refusal.
func TestWorkflowGuardIsTheAdminRoleItselfAndNotItsComposites(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()

	container, err := s.Clients().ByClientID(ctx, realm.ID, "master-realm")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	all, err := s.Roles().ListClientRoles(ctx, realm.ID, container.ID)
	if err != nil {
		t.Fatalf("ListClientRoles: %v", err)
	}
	if len(all) < 20 {
		t.Fatalf("master-realm holds %d roles, so this is not the sweep it claims", len(all))
	}
	names := make([]string, 0, len(all))
	for _, r := range all {
		names = append(names, r.Name)
	}
	everything := tokenForRoles(t, h, s, realm, names...)

	// The control: this caller really does hold the roles, and they really do
	// open something.
	if w := get(t, h, "/admin/realms/master/users", everything); w.Code != http.StatusOK {
		t.Fatalf("control GET /users: %d %s - the roles did not take, "+
			"so the refusals below measure the assignment rather than the guard",
			w.Code, w.Body)
	}

	for _, path := range []string{
		workflowBase,
		workflowBase + "/anything",
		workflowBase + "/scheduled/anything",
	} {
		if w := get(t, h, path, everything); w.Code != http.StatusForbidden {
			t.Errorf("GET %s with every admin role: %d %s, want 403", path, w.Code, w.Body)
		}
	}
	if w := sendTyped(t, h, http.MethodPost, workflowBase, everything,
		"application/yaml", minimalWorkflow); w.Code != http.StatusForbidden {
		t.Errorf("POST with every admin role: %d %s, want 403", w.Code, w.Body)
	}

	// And `admin` opens it, which is the other half of the measurement.
	if w := get(t, h, workflowBase, adminToken(t, h)); w.Code != http.StatusOK {
		t.Fatalf("GET with admin: %d %s, want 200", w.Code, w.Body)
	}
}

// TestWorkflowReadsNegotiateWithYAMLWinningTies pins the whole Accept table on
// one route.
//
// The goldens hold three rows of it. The other four are here because a golden
// per Accept header would be four more recordings of one body, and because the
// rows that matter most are the ones where nothing matches: `text/html` and
// `text/plain` are **YAML 200s** rather than 406s, which is the opposite of
// what the sibling route beside them does.
func TestWorkflowReadsNegotiateWithYAMLWinningTies(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	if w := sendTyped(t, h, http.MethodPost, workflowBase, admin,
		"application/yaml", minimalWorkflow); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}

	const yaml = "application/yaml;charset=UTF-8"
	const json = "application/json;charset=UTF-8"
	for accept, want := range map[string]string{
		"":                                   yaml,
		"*/*":                                yaml,
		"text/html":                          yaml,
		"text/plain":                         yaml,
		"application/json, application/yaml": yaml,
		"application/yaml":                   yaml,
		"application/json":                   json,
		"application/yaml;q=0.5, application/json": json,
		"application/*": yaml,
	} {
		req := httptest.NewRequest(http.MethodGet, workflowBase, nil)
		req.Header.Set("Authorization", "Bearer "+admin)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if got := w.Header().Get("Content-Type"); got != want {
			t.Errorf("Accept %q: Content-Type %q, want %q", accept, got, want)
		}
		// The header that goes with the media type, on the same response.
		wantFrame := want == json
		if hasFrame := w.Header().Get("X-Frame-Options") != ""; hasFrame != wantFrame {
			t.Errorf("Accept %q: X-Frame-Options present=%v, want %v", accept, hasFrame, wantFrame)
		}
	}
}

// TestWorkflowScheduledReadRefusesYAMLWhereTheOtherReadsDoNot is the pair the
// sentence above needs.
//
// One tag, two reads, opposite answers to an `Accept` neither can serve:
// `/workflows` answers `text/html` with a YAML 200, and
// `/workflows/scheduled/{id}` answers `application/yaml` with a 406. A shared
// negotiation helper written from either one alone gets the other wrong.
func TestWorkflowScheduledReadRefusesYAMLWhereTheOtherReadsDoNot(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	req := httptest.NewRequest(http.MethodGet, workflowBase+"/scheduled/nobody", nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	req.Header.Set("Accept", "application/yaml")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotAcceptable {
		t.Fatalf("scheduled with Accept: application/yaml: %d %s, want 406", w.Code, w.Body)
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"error":"HTTP 406 Not Acceptable"}` {
		t.Errorf("406 body %s", got)
	}

	req = httptest.NewRequest(http.MethodGet, workflowBase, nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	req.Header.Set("Accept", "application/yaml")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("the listing with the same Accept: %d %s, want 200", w.Code, w.Body)
	}
}

// TestWorkflowActivationResolvesTheWorkflowBeforeTheType pins an order two
// goldens can each half-record.
//
// `POST /workflows/nosuch/activate/users/x` - an unknown workflow **and** a
// type that does not route - answers about the workflow with a 400, while the
// same lower-case `users` on a workflow that exists answers the router's 404.
// So the workflow is resolved first even though the type is the segment a
// router would normally reject before any handler ran, and an implementation
// that checked the enum in the mux would get the first of these wrong.
func TestWorkflowActivationResolvesTheWorkflowBeforeTheType(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	if w := sendTyped(t, h, http.MethodPost, workflowBase, admin,
		"application/yaml", "id: wf-order\n"+minimalWorkflow); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}

	w := send(t, h, http.MethodPost, workflowBase+"/nosuch/activate/users/x", admin, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown workflow with a bad type: %d %s, want 400", w.Code, w.Body)
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"error":"Not a valid workflow resource: nosuch"}` {
		t.Errorf("body %s", got)
	}

	w = send(t, h, http.MethodPost, workflowBase+"/wf-order/activate/users/x", admin, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("known workflow with a bad type: %d %s, want 404", w.Code, w.Body)
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"error":"HTTP 404 Not Found"}` {
		t.Errorf("body %s", got)
	}
}

// TestWorkflowActivationSchedulesEveryStepCumulatively pins the arithmetic no
// golden can, because every value in it is a clock reading.
//
// Measured on a live 26.7.1 with a three-step workflow whose `after` values are
// P1D, P2D and P3D: the three `scheduled-at` values came back one, three and
// six days out. Scheduling only the first step, or scheduling all three at the
// same instant, or adding each duration to the activation time rather than to
// the step before, each reproduce one of the three numbers and none of them
// reproduces all three.
func TestWorkflowActivationSchedulesEveryStepCumulatively(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	user := createUserWithPassword(t, s, realm, "gloak-probe-wf-subject", "pw")

	const body = "id: wf-sched\nname: gloak-probe-wf-three\non: user-created\nsteps:\n" +
		"  - uses: disable-user\n    after: P1D\n" +
		"  - uses: delete-user\n    after: P2D\n" +
		"  - uses: notify-user\n    after: P3D\n"
	if w := sendTyped(t, h, http.MethodPost, workflowBase, admin,
		"application/yaml", body); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodPost,
		workflowBase+"/wf-sched/activate/USERS/"+user.ID, admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("activate: %d %s", w.Code, w.Body)
	}

	rows, err := s.Workflows().ScheduledFor(context.Background(), realm.ID, user.ID)
	if err != nil {
		t.Fatalf("ScheduledFor: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("%d scheduled rows, want one per step", len(rows))
	}
	byStep := map[string]int64{}
	wf, err := s.Workflows().ByID(context.Background(), realm.ID, "wf-sched")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	for _, row := range rows {
		byStep[row.StepID] = row.ScheduledAt
		if row.Status != "PENDING" {
			t.Errorf("status %q, want PENDING", row.Status)
		}
	}
	const day = int64(24 * 60 * 60 * 1000)
	first := byStep[wf.Steps[0].ID]
	if got := byStep[wf.Steps[1].ID] - first; got != 2*day {
		t.Errorf("step 2 is %d ms after step 1, want %d", got, 2*day)
	}
	if got := byStep[wf.Steps[2].ID] - byStep[wf.Steps[1].ID]; got != 3*day {
		t.Errorf("step 3 is %d ms after step 2, want %d", got, 3*day)
	}
}

// TestWorkflowDeactivationClearsTheScheduleAndIsSafeWithout is the effect
// behind a 204 that says nothing.
//
// `deactivate` answers 204 whether or not anything was scheduled - measured
// before any activation had run - so the status cannot distinguish a handler
// that clears the schedule from one that does nothing at all.
func TestWorkflowDeactivationClearsTheScheduleAndIsSafeWithout(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	user := createUserWithPassword(t, s, realm, "gloak-probe-wf-subject", "pw")
	if w := sendTyped(t, h, http.MethodPost, workflowBase, admin,
		"application/yaml", "id: wf-deact\n"+minimalWorkflow); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	base := workflowBase + "/wf-deact"

	if w := send(t, h, http.MethodPost, base+"/deactivate/USERS/"+user.ID, admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("deactivate before activate: %d %s, want 204", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodPost, base+"/activate/USERS/"+user.ID, admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("activate: %d %s", w.Code, w.Body)
	}
	if w := get(t, h, workflowBase+"/scheduled/"+user.ID, admin); strings.TrimSpace(w.Body.String()) == "[]" {
		t.Fatal("nothing was scheduled, so the clearing below would prove nothing")
	}
	if w := send(t, h, http.MethodPost, base+"/deactivate/USERS/"+user.ID, admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("deactivate: %d %s", w.Code, w.Body)
	}
	if w := get(t, h, workflowBase+"/scheduled/"+user.ID, admin); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("after deactivate the schedule is %s, want []", w.Body)
	}
}

// TestWorkflowCreateRefusalsAreMeasuredPerFault walks the eight rejections one
// fault at a time.
//
// Every message here was read off a live 26.7.1 with the other seven faults
// absent, which is what makes the table say which check produced which
// sentence rather than which one happened to run first.
func TestWorkflowCreateRefusalsAreMeasuredPerFault(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	if w := sendTyped(t, h, http.MethodPost, workflowBase, admin,
		"application/yaml", "name: gloak-probe-wf-taken\non: user-created\n"+
			"steps:\n  - uses: disable-user\n    after: P5D\n"); w.Code != http.StatusCreated {
		t.Fatalf("seed: %d %s", w.Code, w.Body)
	}

	cases := []struct {
		name   string
		body   string
		status int
		want   string
	}{
		{
			name:   "no name",
			body:   "on: user-created\nsteps:\n  - uses: disable-user\n    after: P5D\n",
			status: http.StatusBadRequest,
			want:   `{"errorMessage":"Workflow name cannot be null or empty."}`,
		},
		{
			name:   "empty name",
			body:   "name: \"\"\non: user-created\nsteps:\n  - uses: disable-user\n    after: P5D\n",
			status: http.StatusBadRequest,
			want:   `{"errorMessage":"Workflow name cannot be null or empty."}`,
		},
		{
			name: "taken name",
			body: "name: gloak-probe-wf-taken\non: user-created\n" +
				"steps:\n  - uses: disable-user\n    after: P5D\n",
			status: http.StatusBadRequest,
			want: `{"errorMessage":"Workflow name must be unique. ` +
				`A workflow with name 'gloak-probe-wf-taken' already exists."}`,
		},
		{
			name: "unknown event",
			body: "name: gloak-probe-wf-a\non: user.create\n" +
				"steps:\n  - uses: disable-user\n    after: P5D\n",
			status: http.StatusBadRequest,
			want:   `{"errorMessage":"Could not find provider factory with id: user.create"}`,
		},
		{
			name: "unknown condition",
			body: "name: gloak-probe-wf-b\non: user-created\nif: no-such-condition\n" +
				"steps:\n  - uses: disable-user\n    after: P5D\n",
			status: http.StatusBadRequest,
			want:   `{"errorMessage":"Could not find provider factory with id: no-such-condition"}`,
		},
		{
			name: "unknown step",
			body: "name: gloak-probe-wf-c\non: user-created\n" +
				"steps:\n  - uses: no-such-step\n    after: P5D\n",
			status: http.StatusBadRequest,
			want:   `{"errorMessage":"Could not find step provider: no-such-step"}`,
		},
		{
			name: "after is not a duration",
			body: "name: gloak-probe-wf-d\non: user-created\n" +
				"steps:\n  - uses: disable-user\n    after: 5 days\n",
			status: http.StatusBadRequest,
			want:   `{"errorMessage":"Step 'after' configuration is not valid: 5 days"}`,
		},
		{
			name:   "no steps",
			body:   "name: gloak-probe-wf-e\non: user-created\n",
			status: http.StatusBadRequest,
			want: `{"errorMessage":"Steps provided should support a single type, ` +
				`actual: USERS, CLIENTS"}`,
		},
		{
			name: "steps of two types",
			body: "name: gloak-probe-wf-f\non: user-created\nsteps:\n" +
				"  - uses: disable-user\n    after: P1D\n" +
				"  - uses: disable-client\n    after: P2D\n",
			status: http.StatusBadRequest,
			want:   `{"errorMessage":"Steps provided are not compatible with each other."}`,
		},
		{
			// `enabled` is in the description's schema and the deserialiser
			// refuses it, so no request can ever set it. Reproduced rather
			// than accepted, which is why internal/model has no column for it.
			name: "the enabled field the schema declares",
			body: "name: gloak-probe-wf-g\nenabled: false\non: user-created\n" +
				"steps:\n  - uses: disable-user\n    after: P5D\n",
			status: http.StatusBadRequest,
			want:   `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`,
		},
		{
			// So is a step's `config`, as a plain map and as the multivalued
			// map the schema declares.
			name: "the config field the schema declares",
			body: "name: gloak-probe-wf-h\non: user-created\nsteps:\n" +
				"  - uses: set-user-attribute\n    after: P5D\n    config:\n      k:\n        - v\n",
			status: http.StatusBadRequest,
			want:   `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`,
		},
		{
			name:   "not YAML at all",
			body:   "not yaml at all: [\n",
			status: http.StatusBadRequest,
			want:   `{"error":"invalid_request","error_description":"Cannot parse the JSON"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := sendTyped(t, h, http.MethodPost, workflowBase, admin, "application/yaml", tc.body)
			if w.Code != tc.status {
				t.Fatalf("%d %s, want %d", w.Code, w.Body, tc.status)
			}
			if got := strings.TrimSpace(w.Body.String()); got != tc.want {
				t.Errorf("body\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

// TestWorkflowEmptyBodyIsA500 is Keycloak's own defect, the same family as an
// empty body on POST /users, and it is reproduced rather than tidied.
func TestWorkflowEmptyBodyIsA500(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	req := httptest.NewRequest(http.MethodPost, workflowBase, strings.NewReader(""))
	req.Header.Set("Content-Type", "application/yaml")
	req.Header.Set("Authorization", "Bearer "+admin)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("%d %s, want 500", w.Code, w.Body)
	}
	const want = `{"error":"unknown_error","error_description":` +
		`"For more on this error consult the server log."}`
	if got := strings.TrimSpace(w.Body.String()); got != want {
		t.Errorf("body %s", got)
	}
}

// TestWorkflowListingFiltersAndPaging pins the three rules that are this
// listing's own and not any other listing's.
//
// `search` is a case-insensitive **substring**; `exact=true` compares the whole
// name; and **either bound alone pages**, which is neither the role listings'
// rule nor the user listing's. A malformed bound is the router's 404 rather
// than an ignored parameter.
func TestWorkflowListingFiltersAndPaging(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	for _, name := range []string{"gloak-probe-zzz", "gloak-probe-aaa", "gloak-probe-mmm"} {
		body := "name: " + name + "\non: user-created\nsteps:\n  - uses: disable-user\n    after: P5D\n"
		if w := sendTyped(t, h, http.MethodPost, workflowBase, admin,
			"application/yaml", body); w.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", name, w.Code, w.Body)
		}
	}
	names := func(query string) string {
		w := get(t, h, workflowBase+query, admin)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", query, w.Code, w.Body)
		}
		var out []string
		for _, line := range strings.Split(w.Body.String(), "\n") {
			if after, ok := strings.CutPrefix(strings.TrimSpace(line), `name: "`); ok {
				out = append(out, strings.TrimSuffix(after, `"`))
			}
		}
		return strings.Join(out, ",")
	}

	// Added zzz, aaa, mmm and served sorted by name, which is why no
	// conformance case masks this listing's order.
	if got := names(""); got != "gloak-probe-aaa,gloak-probe-mmm,gloak-probe-zzz" {
		t.Errorf("listing order %q", got)
	}
	if got := names("?search=AAA"); got != "gloak-probe-aaa" {
		t.Errorf("case-insensitive substring: %q", got)
	}
	if got := names("?search=probe-m"); got != "gloak-probe-mmm" {
		t.Errorf("substring rather than prefix: %q", got)
	}
	if got := names("?exact=true&search=probe-m"); got != "" {
		t.Errorf("exact=true compares the whole name: %q", got)
	}
	if got := names("?exact=true&search=gloak-probe-mmm"); got != "gloak-probe-mmm" {
		t.Errorf("exact=true on the whole name: %q", got)
	}
	// Either bound alone pages.
	if got := names("?max=1"); got != "gloak-probe-aaa" {
		t.Errorf("max alone: %q", got)
	}
	if got := names("?first=2"); got != "gloak-probe-zzz" {
		t.Errorf("first alone: %q", got)
	}
	if got := names("?first=1&max=1"); got != "gloak-probe-mmm" {
		t.Errorf("both bounds: %q", got)
	}
	if w := get(t, h, workflowBase+"?max=abc", admin); w.Code != http.StatusNotFound ||
		strings.TrimSpace(w.Body.String()) != `{"error":"HTTP 404 Not Found"}` {
		t.Errorf("a malformed bound: %d %s", w.Code, w.Body)
	}
}

// TestWorkflowUpdateReplacesRatherThanMerging is the difference a 204 hides.
//
// A PUT that omits `if` clears it and a PUT that names fewer steps loses the
// rest, because the body replaces the workflow. Copying updateClient's merging
// shape here is the mistake AGENTS.md's `PUT` bullet warns about, and its
// status is 204 either way.
func TestWorkflowUpdateReplacesRatherThanMerging(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	const created = "id: wf-put\nname: gloak-probe-wf-put\non: user-created\nif: has-role\n" +
		"schedule:\n  after: P1D\n  batch-size: 25\n" +
		"steps:\n  - uses: disable-user\n    after: P1D\n  - uses: delete-user\n    after: P2D\n"
	if w := sendTyped(t, h, http.MethodPost, workflowBase, admin,
		"application/yaml", created); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}

	const replaced = "name: gloak-probe-wf-put\non: user-created\n" +
		"steps:\n  - uses: notify-user\n    after: P9D\n"
	w := sendTyped(t, h, http.MethodPut, workflowBase+"/wf-put", admin, "application/yaml", replaced)
	if w.Code != http.StatusNoContent {
		t.Fatalf("update: %d %s", w.Code, w.Body)
	}
	// The measured header, on the request Content-Type that decides it.
	if got := w.Header().Get("X-Frame-Options"); got != "" {
		t.Errorf("a 204 answering an application/yaml request carries X-Frame-Options %q", got)
	}

	body := get(t, h, workflowBase+"/wf-put?includeId=false", admin).Body.String()
	const want = "---\nname: \"gloak-probe-wf-put\"\n\"on\": \"user-created\"\nsteps:\n" +
		"- uses: \"notify-user\"\n  after: \"P9D\"\n"
	if body != want {
		t.Errorf("after the update:\n%q\nwant\n%q", body, want)
	}
}

// TestWorkflowDeleteIsNotIdempotent is the one delete in this API that refuses
// a repeat, and it refuses it with a 400 rather than a 404.
func TestWorkflowDeleteIsNotIdempotent(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	if w := sendTyped(t, h, http.MethodPost, workflowBase, admin,
		"application/yaml", "id: wf-del\n"+minimalWorkflow); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodDelete, workflowBase+"/wf-del", admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("first delete: %d %s", w.Code, w.Body)
	}
	w := send(t, h, http.MethodDelete, workflowBase+"/wf-del", admin, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("second delete: %d %s, want 400", w.Code, w.Body)
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"error":"Not a valid workflow resource: wf-del"}` {
		t.Errorf("body %s", got)
	}
}

// TestWorkflowCreateHonoursTheBodyIdAndMintsTheStepId is one request making two
// opposite decisions about an id.
//
// The workflow's own id is taken from the body verbatim - and need not be a
// UUID - while a step's id in the same body is discarded and replaced. Nothing
// about the shapes says which, so an implementation that honoured both or
// neither looks equally reasonable and is measurably wrong either way.
func TestWorkflowCreateHonoursTheBodyIdAndMintsTheStepId(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	const body = "id: not-a-uuid-at-all\nname: gloak-probe-wf-ids\non: user-created\n" +
		"steps:\n  - id: neither-is-this\n    uses: disable-user\n    after: P5D\n"
	w := sendTyped(t, h, http.MethodPost, workflowBase, admin, "application/yaml", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Location"); !strings.HasSuffix(got, "/workflows/not-a-uuid-at-all") {
		t.Errorf("Location %q, want it to end in the body's own id", got)
	}
	// The 201 answering an application/yaml request omits it, the same rule
	// the 204s obey.
	if got := w.Header().Get("X-Frame-Options"); got != "" {
		t.Errorf("the 201 carries X-Frame-Options %q", got)
	}
	if got := w.Header().Get("Content-Type"); got != "" {
		t.Errorf("the 201 carries Content-Type %q, want none", got)
	}

	read := get(t, h, workflowBase+"/not-a-uuid-at-all", admin).Body.String()
	if strings.Contains(read, "neither-is-this") {
		t.Errorf("the step kept the id the body named:\n%s", read)
	}
}

// TestWorkflowIdsAreScopedToTheirRealm is the reason ByID takes a realm.
//
// A workflow of one realm answers `Not a valid workflow resource` in another,
// measured across two realms on a live 26.7.1 - so the realm is part of the
// lookup rather than a check that follows it.
func TestWorkflowIdsAreScopedToTheirRealm(t *testing.T) {
	h, s, _ := newServer(t)
	admin := adminToken(t, h)
	ctx := context.Background()
	other := &model.Realm{ID: model.NewID(), Name: "gloak-probe-wf-other", Enabled: true}
	if err := s.Realms().Create(ctx, other); err != nil {
		t.Fatalf("Realms().Create: %v", err)
	}
	if w := sendTyped(t, h, http.MethodPost, workflowBase, admin,
		"application/yaml", "id: wf-scoped\n"+minimalWorkflow); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}

	w := get(t, h, "/admin/realms/gloak-probe-wf-other/workflows/wf-scoped", admin)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cross-realm read: %d %s, want 400", w.Code, w.Body)
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"error":"Not a valid workflow resource: wf-scoped"}` {
		t.Errorf("body %s", got)
	}
}

// TestWorkflowMigrateTakesStepIdsAndNeedsBoth pins what `from` and `to` are.
//
// They are **step** ids: a provider name is refused with the same sentence a
// workflow id gets, and two real step ids are a 204. Either parameter alone is
// the same message as neither, so the check is on the pair.
func TestWorkflowMigrateTakesStepIdsAndNeedsBoth(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	if w := sendTyped(t, h, http.MethodPost, workflowBase, admin,
		"application/yaml", "id: wf-mig\n"+minimalWorkflow); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	wf, err := s.Workflows().ByID(context.Background(), realm.ID, "wf-mig")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	step := wf.Steps[0].ID

	const missing = `{"errorMessage":"Both 'from' and 'to' step ids must be provided for migration."}`
	for _, query := range []string{"", "?from=" + step, "?to=" + step} {
		w := send(t, h, http.MethodPost, workflowBase+"/migrate"+query, admin, "")
		if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != missing {
			t.Errorf("migrate%s: %d %s", query, w.Code, w.Body)
		}
	}
	w := send(t, h, http.MethodPost, workflowBase+"/migrate?from=disable-user&to="+step, admin, "")
	if w.Code != http.StatusBadRequest ||
		strings.TrimSpace(w.Body.String()) != `{"error":"Not a valid workflow resource: disable-user"}` {
		t.Errorf("a provider name as a step id: %d %s", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodPost,
		workflowBase+"/migrate?from="+step+"&to="+step, admin, ""); w.Code != http.StatusNoContent {
		t.Errorf("two real step ids: %d %s, want 204", w.Code, w.Body)
	}
}

// TestWorkflowStoreFailuresAreNotAuthorizationDecisions covers the paths no
// fixture can reach: a repository that fails must be a 500, never a refusal
// that reads like a measured one.
func TestWorkflowStoreFailuresAreNotAuthorizationDecisions(t *testing.T) {
	h, _, _ := newServerWrapping(t, func(s store.Store) store.Store {
		return &faultyWorkflowStore{Store: s}
	})
	admin := adminToken(t, h)
	for _, probe := range []struct {
		method, path string
	}{
		{http.MethodGet, workflowBase},
		{http.MethodGet, workflowBase + "/anything"},
		{http.MethodGet, workflowBase + "/scheduled/anything"},
		{http.MethodDelete, workflowBase + "/anything"},
	} {
		w := send(t, h, probe.method, probe.path, admin, "")
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s %s: %d %s, want 500", probe.method, probe.path, w.Code, w.Body)
		}
	}
}

// faultyWorkflowStore fails every workflow read with an error that is neither
// ErrNotFound nor ErrConflict, which is the only way to reach the 500 branches.
type faultyWorkflowStore struct{ store.Store }

func (f *faultyWorkflowStore) Workflows() store.WorkflowRepo { return faultyWorkflows{} }

type faultyWorkflows struct{ store.WorkflowRepo }

func (faultyWorkflows) List(context.Context, string) ([]*model.Workflow, error) {
	return nil, errInjected
}

func (faultyWorkflows) ByID(context.Context, string, string) (*model.Workflow, error) {
	return nil, errInjected
}

func (faultyWorkflows) ScheduledFor(context.Context, string, string) ([]model.WorkflowScheduledStep, error) {
	return nil, errInjected
}

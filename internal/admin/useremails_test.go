package admin

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// emailRoutes are the three, in the order this file talks about them.
var emailRoutes = []string{"execute-actions-email", "reset-password-email", "send-verify-email"}

// emailUsers creates one user with an email and one without, and returns their
// ids. The pair is what every two-condition assertion below needs.
func emailUsers(t *testing.T, s store.Store, realm *model.Realm) (withEmail, without string) {
	t.Helper()
	ctx := context.Background()
	a := createUserWithPassword(t, s, realm, "mail-yes", "pw")
	a.Email = "mail-yes@example.invalid"
	if err := s.Users().Update(ctx, a); err != nil {
		t.Fatalf("Users().Update: %v", err)
	}
	b := createUserWithPassword(t, s, realm, "mail-no", "pw")
	return a.ID, b.ID
}

func emailPath(userID, op string) string {
	return "/admin/realms/master/users/" + userID + "/" + op
}

// TestTheEmailWritesAnswerAboutTheUserBeforeAnythingElse is the state half of
// the pair: with no email every one of the three refuses, and with one every
// one of them gets as far as the send.
//
// Both halves are needed. A handler that always answered `User email missing`
// would pass the first half alone, and a handler that never checked would pass
// the second alone.
func TestTheEmailWritesAnswerAboutTheUserBeforeAnythingElse(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	withEmail, without := emailUsers(t, s, realm)

	for _, op := range emailRoutes {
		body := ""
		if op == "execute-actions-email" {
			body = `["UPDATE_PASSWORD"]`
		}
		w := send(t, h, http.MethodPut, emailPath(without, op), admin, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s with no email: %d %s", op, w.Code, w.Body)
		}
		if got, want := w.Body.String(), `{"errorMessage":"User email missing"}`; got != want {
			t.Errorf("%s with no email: %s, want %s", op, got, want)
		}

		if got := send(t, h, http.MethodPut, emailPath(withEmail, op), admin, body).Code; got !=
			http.StatusInternalServerError {
			t.Errorf("%s with an email: %d, want the send failure", op, got)
		}
	}
}

// TestResetPasswordEmailAnswersExecuteActionsEmailsSentence is the measurement
// that says two of the three are one implementation - **including the words
// "execute actions" on a route whose path says nothing about them** - and that
// the third is not.
//
// A shared constant makes the first claim true by construction, which is why
// the third route is asserted here too: it is the row that a single shared
// message would fail.
func TestResetPasswordEmailAnswersExecuteActionsEmailsSentence(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	withEmail, _ := emailUsers(t, s, realm)

	execute := send(t, h, http.MethodPut, emailPath(withEmail, "execute-actions-email"),
		admin, `["UPDATE_PASSWORD"]`).Body.String()
	reset := send(t, h, http.MethodPut, emailPath(withEmail, "reset-password-email"),
		admin, "").Body.String()
	verify := send(t, h, http.MethodPut, emailPath(withEmail, "send-verify-email"),
		admin, "").Body.String()

	if execute != reset {
		t.Errorf("reset-password-email does not echo execute-actions-email:\n%s\n%s", execute, reset)
	}
	if verify == execute {
		t.Errorf("send-verify-email answers the shared sentence; it was measured with its own")
	}
	if got, want := verify, `{"errorMessage":"Failed to send verify email"}`; got != want {
		t.Errorf("send-verify-email: %s, want %s", got, want)
	}
	if !strings.Contains(execute, "Failed to send execute actions email: Invalid sender address 'null'.") {
		t.Errorf("execute-actions-email: %s", execute)
	}
}

// TestOnlyExecuteActionsEmailReadsABody is the cell that stops the three
// sharing one handler on the request side.
//
// `text/plain` is the distinguishing request: the one route with a declared
// @Consumes answers 415 and the other two accept the identical bytes. A body
// that is not JSON at all reaches the send on both of them.
func TestOnlyExecuteActionsEmailReadsABody(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	withEmail, _ := emailUsers(t, s, realm)

	w := sendCT(t, h, http.MethodPut, emailPath(withEmail, "execute-actions-email"),
		admin, "text/plain", "x")
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("execute-actions-email with text/plain: %d %s", w.Code, w.Body)
	}
	if got, want := w.Body.String(),
		`{"error":"The content-type header value did not match the value in @Consumes"}`; got != want {
		t.Errorf("the 415 body: %s, want %s", got, want)
	}

	for _, op := range []string{"reset-password-email", "send-verify-email"} {
		w := sendCT(t, h, http.MethodPut, emailPath(withEmail, op), admin, "text/plain", "not json at all")
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s with text/plain: %d %s, want it to be ignored", op, w.Code, w.Body)
		}
	}
}

// TestExecuteActionsEmailBodyShapes: two codes for two shapes, and the `[` row
// is a **third** answer to the same bytes that get unknown_error on POST /users
// and invalid_request on the ten role-array endpoints.
func TestExecuteActionsEmailBodyShapes(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	withEmail, _ := emailUsers(t, s, realm)
	path := emailPath(withEmail, "execute-actions-email")

	for _, tc := range []struct{ name, body, want string }{
		{"a truncated array", `[`,
			`{"error":"HTTP 400 Bad Request","error_description":"Cannot parse the JSON"}`},
		{"an object", `{}`,
			`{"error":"unknown_error","error_description":"Cannot parse the JSON"}`},
		{"a truncated object", `{`,
			`{"error":"unknown_error","error_description":"Cannot parse the JSON"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := send(t, h, http.MethodPut, path, admin, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if got := w.Body.String(); got != tc.want {
				t.Errorf("\n got %s\nwant %s", got, tc.want)
			}
		})
	}
	// An empty array, a literal null and no body at all all reach the send, so
	// emptiness is not a refusal on this route.
	for _, body := range []string{`[]`, `null`, ``} {
		if got := send(t, h, http.MethodPut, path, admin, body).Code; got != http.StatusInternalServerError {
			t.Errorf("body %q: %d, want the send failure", body, got)
		}
	}
}

// TestResetPasswordEmailIgnoresLifespanAndItsNeighboursDoNot is the cell that
// keeps the three as three handlers.
//
// One parameter, three routes, two answers - and the vendored description
// agrees, giving `reset-password-email` no `lifespan` where it gives the other
// two one. Two independent sources, which is worth having because they disagree
// about this family's responses elsewhere.
func TestResetPasswordEmailIgnoresLifespanAndItsNeighboursDoNot(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	withEmail, _ := emailUsers(t, s, realm)

	for _, tc := range []struct {
		op   string
		body string
		want int
	}{
		{"execute-actions-email", `["UPDATE_PASSWORD"]`, http.StatusNotFound},
		{"send-verify-email", "", http.StatusNotFound},
		{"reset-password-email", "", http.StatusInternalServerError},
	} {
		w := send(t, h, http.MethodPut, emailPath(withEmail, tc.op)+"?lifespan=abc", admin, tc.body)
		if w.Code != tc.want {
			t.Errorf("%s with lifespan=abc: %d, want %d (%s)", tc.op, w.Code, tc.want, w.Body)
		}
		if tc.want == http.StatusNotFound {
			if got, want := w.Body.String(), `{"error":"HTTP 404 Not Found"}`; got != want {
				t.Errorf("%s: %s, want %s", tc.op, got, want)
			}
		}
		// The control: a well-formed bound changes nothing on any of the three.
		if got := send(t, h, http.MethodPut, emailPath(withEmail, tc.op)+"?lifespan=60",
			admin, tc.body).Code; got != http.StatusInternalServerError {
			t.Errorf("%s with lifespan=60: %d, want the send failure", tc.op, got)
		}
	}
}

// TestTheEmailRejectionOrder is the ten-step order, and **every row is a
// request wrong in two ways**. A request wrong in one way cannot say which
// check ran first, which is the shape eleven survivors in this repository have
// had.
func TestTheEmailRejectionOrder(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	withEmail, without := emailUsers(t, s, realm)
	const bogusUser = "00000000-0000-0000-0000-0000000000ff"

	for _, tc := range []struct {
		name, path, body, want string
	}{
		{
			"an unknown subject beats an unknown client",
			emailPath(bogusUser, "execute-actions-email") + "?client_id=nosuch",
			`["UPDATE_PASSWORD"]`, `{"error":"User not found"}`,
		},
		{
			"an unknown subject beats a malformed lifespan",
			emailPath(bogusUser, "execute-actions-email") + "?lifespan=abc",
			`["UPDATE_PASSWORD"]`, `{"error":"User not found"}`,
		},
		{
			"a malformed body beats a missing email",
			emailPath(without, "execute-actions-email"), `[`,
			`{"error":"HTTP 400 Bad Request","error_description":"Cannot parse the JSON"}`,
		},
		{
			"a malformed body beats an unknown client",
			emailPath(withEmail, "execute-actions-email") + "?client_id=nosuch", `[`,
			`{"error":"HTTP 400 Bad Request","error_description":"Cannot parse the JSON"}`,
		},
		{
			"a malformed lifespan beats a missing email",
			emailPath(without, "execute-actions-email") + "?lifespan=abc",
			`["UPDATE_PASSWORD"]`, `{"error":"HTTP 404 Not Found"}`,
		},
		{
			"a malformed lifespan beats an unknown client",
			emailPath(withEmail, "execute-actions-email") + "?client_id=nosuch&lifespan=abc",
			`["UPDATE_PASSWORD"]`, `{"error":"HTTP 404 Not Found"}`,
		},
		{
			"a missing email beats an unknown client",
			emailPath(without, "execute-actions-email") + "?client_id=nosuch",
			`["UPDATE_PASSWORD"]`, `{"errorMessage":"User email missing"}`,
		},
		{
			"a missing email beats a bogus action",
			emailPath(without, "execute-actions-email"), `["NOSUCHACTION"]`,
			`{"errorMessage":"User email missing"}`,
		},
		{
			"an unknown client beats a bogus action",
			emailPath(withEmail, "execute-actions-email") + "?client_id=nosuch",
			`["NOSUCHACTION"]`, `{"errorMessage":"Client doesn't exist"}`,
		},
		{
			"a redirect_uri with no client_id",
			emailPath(withEmail, "execute-actions-email") + "?redirect_uri=http%3A%2F%2Fx.invalid%2F",
			`["UPDATE_PASSWORD"]`, `{"errorMessage":"Client id missing"}`,
		},
		{
			"a bogus action, with nothing else wrong",
			emailPath(withEmail, "execute-actions-email"), `["NOSUCHACTION"]`,
			`{"errorMessage":"Provided invalid required actions"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := send(t, h, http.MethodPut, tc.path, admin, tc.body).Body.String(); got != tc.want {
				t.Errorf("\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

// TestARealRequiredActionIsAccepted is the other side of the action check, and
// it reads the realm's own rows rather than a constant - a **disabled** alias is
// accepted, which is what says the check is existence and not enabledness.
func TestARealRequiredActionIsAccepted(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	withEmail, _ := emailUsers(t, s, realm)
	path := emailPath(withEmail, "execute-actions-email")

	rows, err := s.RequiredActions().ListByRealm(context.Background(), realm.ID)
	if err != nil || len(rows) == 0 {
		t.Fatalf("no required actions to test with: %v", err)
	}
	var disabled string
	for _, row := range rows {
		if !row.Enabled {
			disabled = row.Alias
		}
	}
	if got := send(t, h, http.MethodPut, path, admin,
		`["`+rows[0].Alias+`"]`).Code; got != http.StatusInternalServerError {
		t.Errorf("%s was refused: %d", rows[0].Alias, got)
	}
	if disabled == "" {
		t.Skip("no disabled required action in this realm")
	}
	if got := send(t, h, http.MethodPut, path, admin,
		`["`+disabled+`"]`).Code; got != http.StatusInternalServerError {
		t.Errorf("the disabled alias %s was refused: %d", disabled, got)
	}
}

// TestTheEmailWritesTakeManageUsersAlone, with the two-stage guard visible on
// every row: the roles inside the users family still resolve the subject and
// answer 404 for one that does not exist, and the roles outside it answer 403
// to the same request.
func TestTheEmailWritesTakeManageUsersAlone(t *testing.T) {
	h, s, realm := newServer(t)
	withEmail, _ := emailUsers(t, s, realm)
	const bogusUser = "00000000-0000-0000-0000-0000000000ff"

	for _, tc := range []struct {
		role            string
		want            int
		unknownSubject  int
		subjectResolved bool
	}{
		{"manage-users", http.StatusInternalServerError, http.StatusNotFound, true},
		{"view-users", http.StatusForbidden, http.StatusNotFound, true},
		{"query-users", http.StatusForbidden, http.StatusNotFound, true},
		{"view-realm", http.StatusForbidden, http.StatusForbidden, false},
		{"manage-realm", http.StatusForbidden, http.StatusForbidden, false},
		{"view-clients", http.StatusForbidden, http.StatusForbidden, false},
		{"manage-clients", http.StatusForbidden, http.StatusForbidden, false},
		{"impersonation", http.StatusForbidden, http.StatusForbidden, false},
	} {
		token := tokenForRole(t, h, s, realm, tc.role)
		for _, op := range emailRoutes {
			body := ""
			if op == "execute-actions-email" {
				body = `["UPDATE_PASSWORD"]`
			}
			if got := send(t, h, http.MethodPut, emailPath(withEmail, op), token, body).Code; got != tc.want {
				t.Errorf("%s on %s: %d, want %d", tc.role, op, got, tc.want)
			}
		}
		got := send(t, h, http.MethodPut, emailPath(bogusUser, "execute-actions-email"),
			token, `["UPDATE_PASSWORD"]`).Code
		if got != tc.unknownSubject {
			t.Errorf("%s on an unknown subject: %d, want %d", tc.role, got, tc.unknownSubject)
		}
	}
	// No token at all, on all three.
	for _, op := range emailRoutes {
		if got := send(t, h, http.MethodPut, emailPath(withEmail, op), "", "").Code; got !=
			http.StatusUnauthorized {
			t.Errorf("%s with no token: %d, want 401", op, got)
		}
	}
}

// TestAKnownClientReachesTheSend is the accepting half of the client check.
// Without it a handler that refused every client_id would pass every refusal
// row above.
func TestAKnownClientReachesTheSend(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	withEmail, _ := emailUsers(t, s, realm)

	for _, op := range emailRoutes {
		body := ""
		if op == "execute-actions-email" {
			body = `["UPDATE_PASSWORD"]`
		}
		if got := send(t, h, http.MethodPut, emailPath(withEmail, op)+"?client_id=account",
			admin, body).Code; got != http.StatusInternalServerError {
			t.Errorf("%s with a real client: %d, want the send failure", op, got)
		}
	}
}

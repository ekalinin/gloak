package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
)

// The three email writes of the `Users` tag, and the decision that shapes them.
//
// **They are a mail client, not three operations** - and this file serves the
// part of them that is not.
//
// Measured over four states on 2026-09-06, the realm's `smtpServer` changed
// between blocks and re-read each time, so a block answering what the block
// before it answered would have been a block whose state did not move:
//
//	smtpServer     the user has an email   answer
//	any            no                      400 {"errorMessage":"User email missing"}
//	{}             yes                     500 … Invalid sender address 'null'. …
//	unreachable    yes                     500 … Error when attempting to send the email to the server. …
//	reachable      yes                     204, and the message really arrives
//
// The last two rows are what a mail client buys, and **neither is reachable in
// Gloak** - not because of this cut, and not because of the mail client.
// `internal/admin/realmrep.go` builds every realm representation with
// `SMTPServer: map[string]string{}`, a literal that is never read from storage
// and never written to it, so a Gloak realm's `smtpServer` is `{}` for ever.
// Row three needs a stored one and row four needs that as well as a transport
// and Keycloak's message templates.
//
// So serving rows one and two is not three quarters of an operation. It is the
// shape `configured-user-storage-credential-types` already has in
// userprofile.go and `client-types`' 501 has in managementpermissions.go: **a
// constant that is a contract because the state behind the other branch cannot
// be reached.** What is different here, and is why it is filed rather than left
// implicit, is that this one becomes reachable the day a cut stores
// `smtpServer` - and both bodies are recorded in the follow-ups so that cut does
// not have to measure them again.
//
// # The three are one implementation and two of them prove it
//
// `reset-password-email` answers `execute-actions-email`'s 500 **word for
// word**, including the words "execute actions", which is what says the two
// share a code path rather than merely a shape. `send-verify-email` answers its
// own constant in both failing states and interpolates nothing.
//
// What separates them is what they read, and the live server and the vendored
// description agree on it - worth saying, because they disagree about the
// responses, the description giving `send-verify-email` no 404 where the server
// sends one:
//
//	                        body   client_id  redirect_uri  lifespan
//	execute-actions-email    yes       yes         yes        yes
//	reset-password-email      no       yes         yes        **no**
//	send-verify-email         no       yes         yes        yes
//
// `reset-password-email` ignoring `lifespan` is measured on the request that
// separates it from its neighbours: `?lifespan=abc` is the generic
// `404 {"error":"HTTP 404 Not Found"}` on the other two and a plain 500 here.
// And `execute-actions-email` is the only one that reads a body at all, which is
// also the only one that answers `text/plain` a 415 - the other two accept any
// body under any Content-Type and ignore both.

// executeActionsEmailFailure is the sentence two of the three answer when the
// realm's SMTP cannot send. It names "execute actions" on **both** of them:
// `reset-password-email` echoes it unchanged, which is the measurement that
// says the pair is one implementation.
const executeActionsEmailFailure = "Failed to send execute actions email: Invalid sender address " +
	"'null'. If the address contains UTF-8 characters in the local part please ensure the SMTP " +
	"server supports the SMTPUTF8 extension and enable 'Allow UTF-8' in the email realm configuration."

// verifyEmailFailure is send-verify-email's own constant. It interpolates
// nothing and is the same in every failing state.
const verifyEmailFailure = "Failed to send verify email"

// executeActionsEmail serves
// PUT /admin/realms/{realm}/users/{user-id}/execute-actions-email.
//
// The rejection order is ten deep and **every adjacency below was decided by a
// request wrong in two ways**, because a request wrong in one way cannot say
// which check ran first:
//
//	1  no token          401 {"error":"HTTP 401 Unauthorized"}
//	2  the coarse gate   403 to view-clients, manage-realm, impersonation, …
//	3  the subject       404 {"error":"User not found"}   - beats 4..10
//	4  manage-users      403 to view-users and query-users
//	5  the body          400 HTTP 400 Bad Request / Cannot parse the JSON  - beats 6..10
//	6  lifespan          404 {"error":"HTTP 404 Not Found"}                - beats 7..10
//	7  the user's email  400 {"errorMessage":"User email missing"}         - beats 8..10
//	8  client_id         400 {"errorMessage":"Client doesn't exist"}
//	                     400 {"errorMessage":"Client id missing"} with a redirect_uri and no client
//	9  redirect_uri      400 {"errorMessage":"Invalid redirect uri."}
//	10 the actions       400 {"errorMessage":"Provided invalid required actions"}
//
// **Step 7 beating step 10 is the two-condition cell**: a user with no email
// *and* a bogus action answers about the email, and the identical bogus action
// on a user with an email answers about the action. One request supplies one
// condition and says nothing at all about the order.
//
// Steps 1 to 4 are guardUserSubject with userWriteRoles, which is the
// combinator and the role set every other write in this family already uses -
// measured here rather than inherited, one role at a time over eight roles.
func (h *handler) executeActionsEmail(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if !requireJSONBody(w, r) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	actions, ok := decodeRequiredActions(w, body)
	if !ok {
		return
	}
	if !parsedLifespan(w, r) {
		return
	}
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	if !h.emailSendable(w, r, rc, user) {
		return
	}
	// **The actions are checked last**, after the email and after the client.
	// Every alias the realm's required actions declare is accepted, registered
	// or not; anything else is the one sentence, which names neither the action
	// nor how many were wrong.
	if !h.knownRequiredActions(r, rc, actions) {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Provided invalid required actions")
		return
	}
	httpx.WriteAdminError(w, http.StatusInternalServerError, executeActionsEmailFailure)
}

// resetPasswordEmail serves
// PUT /admin/realms/{realm}/users/{user-id}/reset-password-email.
//
// It reads **no body and no lifespan**, and answers execute-actions-email's
// sentence unchanged. Both halves are measured on requests that separate it
// from its neighbours: `text/plain` carrying junk is accepted where the sibling
// answers 415, and `?lifespan=abc` falls through to the 500 where the sibling
// answers the generic 404.
func (h *handler) resetPasswordEmail(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	if !h.emailSendable(w, r, rc, user) {
		return
	}
	httpx.WriteAdminError(w, http.StatusInternalServerError, executeActionsEmailFailure)
}

// sendVerifyEmail serves
// PUT /admin/realms/{realm}/users/{user-id}/send-verify-email.
//
// It reads no body and **does** read `lifespan`, which is the cell that stops
// this and resetPasswordEmail sharing one handler: one of the three parameters
// is per route rather than per family.
func (h *handler) sendVerifyEmail(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if !parsedLifespan(w, r) {
		return
	}
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	if !h.emailSendable(w, r, rc, user) {
		return
	}
	httpx.WriteAdminError(w, http.StatusInternalServerError, verifyEmailFailure)
}

// emailSendable runs the three checks the three routes share, in the measured
// order, and reports whether the caller has got as far as the send.
//
// It returns false having written the refusal. It never returns true with the
// mail sent, because nothing here sends mail - see this file's header for why
// the two states beyond this point cannot be reached on a Gloak realm.
func (h *handler) emailSendable(w http.ResponseWriter, r *http.Request, rc *reqContext,
	user *model.User) bool {
	if user.Email == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "User email missing")
		return false
	}
	return h.emailRedirectAccepted(w, r, rc)
}

// emailRedirectAccepted checks `client_id`, which all three routes read and
// which runs **after** the user's email.
//
// Two of the three measured cells are served here:
//
//	client_id names nothing          400 {"errorMessage":"Client doesn't exist"}
//	a redirect_uri and no client_id  400 {"errorMessage":"Client id missing"}
//	a redirect_uri the client has not 400 {"errorMessage":"Invalid redirect uri."}
//
// **The full stop is on the third and not on the other two**, which is another
// pair of neighbouring messages in this API separated by punctuation alone.
//
// # The third cell is deliberately not served, and it is F148's shape
//
// Deciding whether a `redirect_uri` matches a client's registered patterns is
// `matchRedirectURI` in internal/oidc/authorize.go, which is unexported and in a
// package this branch may not touch. AGENTS.md records that rule at length -
// nothing is normalised, a wildcard is not a bare prefix, the query and fragment
// are cut in the wildcard branch **only** - and records that this project got it
// wrong once already. Writing a second one here would be the second copy F148
// exists to prevent, applied to an error branch rather than to a whole
// operation, and a second copy of a rule with eight recorded corner cases is a
// second copy that will diverge.
//
// So a `redirect_uri` that resolves against no pattern reaches the send instead
// of the 400. That is a **declared divergence with an alarm on it** rather than
// a silence: `admin/users/execute-actions-email-bad-redirect` carries Keycloak's
// bytes as a `Recorded` case, so the day the matcher moves somewhere both
// packages can reach, the suite fails with "already matches" and tells whoever
// did it to promote the case.
func (h *handler) emailRedirectAccepted(w http.ResponseWriter, r *http.Request, rc *reqContext) bool {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	if clientID == "" {
		if q.Get("redirect_uri") == "" {
			return true
		}
		httpx.WriteAdminError(w, http.StatusBadRequest, "Client id missing")
		return false
	}
	if _, err := h.store.Clients().ByClientID(r.Context(), rc.realm.ID, clientID); err != nil {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Client doesn't exist")
		return false
	}
	return true
}

// decodeRequiredActions reads execute-actions-email's body, which is an array
// of required action aliases.
//
// **Three bodies, three answers, and the code follows the body's shape rather
// than the endpoint** - which is what AGENTS.md already records and this is a
// fourth data point for. `{` and `{}` are `unknown_error`, an object where an
// array is wanted; `[` is **`HTTP 400 Bad Request`**, which is a third code for
// the same bytes that answer `unknown_error` on `POST /users` and
// `invalid_request` on the ten role-array endpoints.
//
// An absent body, a literal `null` and an empty array all pass through as no
// actions and reach the send, so emptiness is not a refusal here.
func decodeRequiredActions(w http.ResponseWriter, body []byte) ([]string, bool) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "null" {
		return nil, true
	}
	var actions []string
	if err := json.Unmarshal(body, &actions); err != nil {
		code := "unknown_error"
		if trimmed[0] == '[' {
			code = "HTTP 400 Bad Request"
		}
		httpx.WriteOAuthError(w, http.StatusBadRequest, code, "Cannot parse the JSON")
		return nil, false
	}
	return actions, true
}

// parsedLifespan reads the `lifespan` bound, which two of the three routes have.
//
// A value that is not an integer is the generic
// `404 {"error":"HTTP 404 Not Found"}` - the malformed-integer-bound producer
// AGENTS.md counts, met on a **write** rather than on a listing. The value
// itself is not used: nothing here mints a link, and a well-formed `?lifespan=60`
// reaches the same 500 that no lifespan at all does.
func parsedLifespan(w http.ResponseWriter, r *http.Request) bool {
	raw := r.URL.Query().Get("lifespan")
	if raw == "" {
		return true
	}
	if _, err := strconv.Atoi(raw); err != nil {
		httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
		return false
	}
	return true
}

// knownRequiredActions reports whether every alias the body named is one the
// realm has.
//
// It reads the realm's required action rows rather than a constant, because the
// set is per realm: a realm that registers a provider gains an alias, and the
// endpoint accepts a **disabled** one - which is why this asks whether the row
// exists and never whether it is enabled.
func (h *handler) knownRequiredActions(r *http.Request, rc *reqContext, actions []string) bool {
	if len(actions) == 0 {
		return true
	}
	rows, err := h.store.RequiredActions().ListByRealm(r.Context(), rc.realm.ID)
	if err != nil {
		return false
	}
	known := make(map[string]bool, len(rows))
	for _, row := range rows {
		known[row.Alias] = true
	}
	for _, a := range actions {
		if !known[a] {
			return false
		}
	}
	return true
}

package admin

import (
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
)

// The `Attack Detection` tag, all three of its operations.
//
// **Gloak has no brute-force detector, and that is what shapes this file.** The
// realm representation serves `bruteForceProtected` and the eleven tuning
// fields beside it and nothing reads them; no path in this tree counts a failed
// login. So the zero record below is not a default chosen here - it is the only
// state Gloak can reach, for every request the Admin API can be given.
//
// That makes the file honest rather than a stub in one specific sense: for
// every input, these three routes answer byte for byte what Keycloak answers.
// What is missing is the detector that would make another answer possible, and
// it lives on the login path rather than here. See F157.
//
// It is also why there is no table. A column nothing writes is a claim about
// the model that is not true, and it is the storage equivalent of the inert
// masks AGENTS.md removed 116 of. The table arrives with the thing that fills
// it.

// bruteForceStatus is what `GET .../attack-detection/brute-force/users/{id}`
// serves, in the measured key order.
//
// Keycloak builds it from a `HashMap<String,Object>`, so the order is
// `javamap.KeyOrder`'s over the seven names - confirmed: the function returns
// `failedLoginNotBefore, numFailures, numTemporaryLockouts, disabled,
// numSecondaryAuthFailures, lastIPFailure, lastFailure`, which is the measured
// body byte for byte. Nothing here calls javamap, because a struct with the
// fields in that order reproduces it and the seven names are fixed; the
// fifteenth measured key set is recorded in the plan rather than pinned as a
// vector, since it collides in no bucket and both constructors agree on it.
//
// **The two time fields are in different units on one body.**
// `failedLoginNotBefore` is seconds and `lastFailure` is milliseconds -
// measured on one locked-out user as 1788527963 against 1788527903483, which
// is the same instant plus the sixty-second quick-login wait. Serving both from
// one clock helper is the tidy-up that is wrong by a factor of a thousand on
// one of them.
type bruteForceStatus struct {
	FailedLoginNotBefore     int64  `json:"failedLoginNotBefore"`
	NumFailures              int    `json:"numFailures"`
	NumTemporaryLockouts     int    `json:"numTemporaryLockouts"`
	Disabled                 bool   `json:"disabled"`
	NumSecondaryAuthFailures int    `json:"numSecondaryAuthFailures"`
	LastIPFailure            string `json:"lastIPFailure"`
	LastFailure              int64  `json:"lastFailure"`
}

// noBruteForceRecord is the body for a user with no failures.
//
// `lastIPFailure` is the string `n/a` rather than an empty string or a null,
// which is the one value in the record that cannot be guessed from its type.
var noBruteForceRecord = bruteForceStatus{LastIPFailure: "n/a"}

// readBruteForceStatus serves
// GET /admin/realms/{realm}/attack-detection/brute-force/users/{userId}.
//
// **There is no 404 branch, and that is measured rather than an omission.** A
// user id that resolves to nothing answers 200 with the same zero record a real
// user with no failures gets - so the route does not resolve the user at all,
// and adding a lookup to "be safe" would invent a status Keycloak does not
// send. The read is authorised out of the *users* pair, which is the finding:
// nothing in the path or the tag says users, and `query-users` - which opens
// `GET /users` - is 403 here.
func (h *handler) readBruteForceStatus(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	writeAdminJSON(w, noBruteForceRecord)
}

// clearBruteForceForUser serves
// DELETE /admin/realms/{realm}/attack-detection/brute-force/users/{userId}, and
// clearBruteForceForRealm the collection delete beside it.
//
// Both are 204 with no `Cache-Control`, and both clear nothing here because
// nothing writes anything to clear. The unknown-id case is 204 on the server
// too, so the two handlers are one answer rather than a lookup.
func (h *handler) clearBruteForceForUser(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	httpx.WriteNoContent(w, r)
}

func (h *handler) clearBruteForceForRealm(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	httpx.WriteNoContent(w, r)
}

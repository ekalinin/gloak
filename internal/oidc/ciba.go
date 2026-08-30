package oidc

import (
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
)

// Client Initiated Backchannel Authentication, OpenID Connect CIBA: the
// backchannel authentication endpoint and the token endpoint's grant.
//
// **CIBA cannot complete on a default Keycloak 26.7.1, and that is the
// contract rather than a gap in this implementation.** A client carrying
// oidc.ciba.grant.enabled sending a well-formed request answers 503:
//
//	{"error":"server_error","error_description":"Failed to send authentication request"}
//
// and the container log says why:
//
//	java.lang.RuntimeException: Authentication Channel Request URI not set properly.
//	  at ...ciba.channel.HttpAuthenticationChannelProvider.checkAuthenticationChannel
//
// The default ciba-http-auth-channel provider needs
// spi-ciba-auth-channel-ciba-http-auth-channel-http-authentication-channel-uri,
// an external HTTP endpoint that start-dev does not configure. So a default
// deployment has no auth_req_id to be had, which is the same situation as
// `client-types` answering 501 and `.../client-secret/rotated` answering a
// permanent 404: the refusal *is* what the endpoint serves.
//
// It is also why oidc/ciba/poll-pending and oidc/ciba/poll-complete stay
// Pending. They are not unimplemented, they are **unmeasurable** in this
// project's container regime, and their reason says so.
//
// Measured 2026-08-30. See the plan's section 1.4.

// grantCIBA is the token endpoint's grant type for a CIBA authentication
// request. It is already in the discovery document's grant_types_supported.
const grantCIBA = "urn:openid:params:grant-type:ciba"

// attrCIBAGrantEnabled is the client attribute both CIBA endpoints gate on. It
// is off on every client of a default 26.7.1.
const attrCIBAGrantEnabled = "oidc.ciba.grant.enabled"

// CIBA's measured descriptions.
//
// **The grant-disabled answer is one string with two statuses**: 401 at the
// backchannel endpoint and 400 at the token endpoint, with `invalid_grant` on
// both. That is the mirror image of the device grant, whose two endpoints agree
// on nothing - two strings and two codes. Two families, two different ways of
// disagreeing, and one shared constant is right here and wrong there.
//
// descCIBAMissingScope and descCIBAMissingLoginHint have a space on **both**
// sides of the colon and are lower case, where every other missing-parameter
// description on the protocol side is "Missing parameter: x". The token
// endpoint's auth_req_id message below is that ordinary spelling, so the two
// conventions live one endpoint apart.
const (
	descCIBAGrantOff       = "Client not allowed OIDC CIBA Grant"
	descCIBAMissingScope   = "missing parameter : scope"
	descCIBAMissingHint    = "missing parameter : login_hint"
	descCIBAInvalidUser    = "invalid_user"
	descCIBAChannelFailed  = "Failed to send authentication request"
	descMissingAuthReqID   = "Missing parameter: auth_req_id"
	descInvalidAuthReqID   = "Invalid Auth Req ID"
	cibaErrServerError     = "server_error"
	cibaErrInvalidGrantStr = "invalid_grant"
)

// backchannelAuthentication serves
// POST /realms/{realm}/protocol/openid-connect/ext/ciba/auth.
//
// The order is measured, one pair of faults per adjacency, and **three of the
// six steps are not where a reader would put them**:
//
//  1. the realm                  404 Realm does not exist
//
//  2. client authentication      401
//
//  3. the CIBA grant flag        401 invalid_grant  Client not allowed OIDC CIBA Grant
//
//  4. login_hint **present**     400 invalid_request  missing parameter : login_hint
//
//  5. scope **present**          400 invalid_request  missing parameter : scope
//
//  6. login_hint **resolves**    400 invalid_request  invalid_user
//
//  7. scope **valid**            400 invalid_scope    Invalid scopes: <raw>
//
//  8. the authentication channel 503 server_error     Failed to send authentication request
//
//     - **login_hint is checked before scope**, so a request missing both is told
//     about the hint. The obvious order is the one the parameters are listed in
//     and it is the wrong one.
//     - **Presence and value are two different steps with two different answers,
//     and they interleave.** An empty `scope=` is not "missing parameter" - it
//     passes step 5 and fails step 7 with `Invalid scopes: ` and its trailing
//     space. An empty `login_hint=` passes step 4 and fails step 6. So a single
//     `Get(...) == ""` check per parameter, which is what this function did when
//     it was first written, gets both of them wrong.
//     - **Step 6 is between them**, so an empty scope with an unresolvable hint
//     answers about the hint. Measured on both halves of that pair.
//
// **There is no duplicated-parameter check on this endpoint at all**: `zz`
// twice and `login_hint` twice both reach the 503, where `/auth/device` and the
// token endpoint each answer `duplicated parameter`. Three endpoints in one
// protocol, two of them checking and one not.
//
// Like the device endpoint, no response here carries Cache-Control or Pragma.
func (h *handler) backchannelAuthentication(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, "Invalid request")
		return
	}
	client, authErr := h.authenticateClient(r.Context(), realm, r.PostForm, r.Header)
	if authErr != nil {
		authErr.write(w)
		return
	}
	// 401, not 400 - the one place the two CIBA endpoints differ on this
	// condition.
	if !cibaGrantEnabled(client) {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, cibaErrInvalidGrantStr, descCIBAGrantOff)
		return
	}
	hint, hintPresent := r.PostForm["login_hint"]
	if !hintPresent {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descCIBAMissingHint)
		return
	}
	scope, scopePresent := r.PostForm["scope"]
	if !scopePresent {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descCIBAMissingScope)
		return
	}
	// invalid_user covers both an empty hint and one naming nobody - measured
	// on both, which is what says the check is the lookup rather than the
	// value. It is invalid_request rather than invalid_grant, and the
	// description is lower case with an underscore, like /auth's
	// authentication_expired and unlike everything else on this endpoint.
	if _, err := h.store.Users().ByUsername(r.Context(), realm.ID, hint[0]); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descCIBAInvalidUser)
		return
	}
	// The raw parameter is echoed, doubled spaces and all, which is why
	// scopesAllowed takes the string rather than the parsed words. It is the
	// authorization endpoint's own predicate: an empty scope= is refused, and
	// openid is allowed on top of the client's two lists.
	if !scopesAllowed(client, scope[0]) {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidScope, "Invalid scopes: "+scope[0])
		return
	}
	// Everything a default deployment can answer has now been answered. The
	// authentication channel is what would mint an auth_req_id, and a default
	// 26.7.1 has none configured, so this is the measured end of the road
	// rather than a stub standing in for work.
	httpx.WriteOAuthError(w, http.StatusServiceUnavailable, cibaErrServerError, descCIBAChannelFailed)
}

// cibaGrant is the token endpoint's half. There is no auth_req_id a default
// deployment could have issued, so the only reachable answers are the three
// measured refusals - and the third, "Invalid Auth Req ID", is what every
// syntactically anything answers.
func (h *handler) cibaGrant(w http.ResponseWriter, r *http.Request, client *model.Client) {
	if !cibaGrantEnabled(client) {
		httpx.WriteOAuthError(w, http.StatusBadRequest, cibaErrInvalidGrantStr, descCIBAGrantOff)
		return
	}
	if _, present := r.PostForm["auth_req_id"]; !present {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descMissingAuthReqID)
		return
	}
	httpx.WriteOAuthError(w, http.StatusBadRequest, cibaErrInvalidGrantStr, descInvalidAuthReqID)
}

func cibaGrantEnabled(c *model.Client) bool {
	return c.Attributes[attrCIBAGrantEnabled] == "true"
}

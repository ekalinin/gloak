// Package oidc serves the OpenID Connect protocol endpoints built so far:
// discovery, JWKS and the realm's public info endpoint. Token issuance and
// the browser flow are separate, later plans.
package oidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

type handler struct {
	store      store.Store
	keys       *keys.Manager
	issuerBase string
	// auth holds the browser flow's authentication sessions and authorization
	// codes, in memory. See internal/oidc/authsession.go for why that is the
	// faithful model and what it costs: this cut is single-process.
	auth *authStore
	// device holds the device authorization grant's codes, in memory for the
	// same reason and at the same cost. See internal/oidc/devicestore.go.
	device *deviceStore
	// consents holds which clients a user has approved, in memory for a reason
	// that is **not** the other two's: Keycloak persists a consent and a user can
	// revoke it through the Admin API, so this one is a divergence rather than
	// the faithful model. See internal/oidc/authsession.go.
	consents *consentStore
	// registrations holds which registration access token is current for a
	// client. **The registered client itself is persisted** through
	// store.ClientRepo; only the token's identity is in memory, and
	// internal/oidc/registrationstore.go says why and what it costs.
	registrations *registrationStore
	// proofs holds the jti of every DPoP proof spent recently, so that one
	// cannot be replayed. In memory, F75's shape - Keycloak keeps it in
	// Infinispan. See internal/oidc/dpop.go.
	proofs *proofStore
	// httpClient is the one place this package calls *out*, and it exists for
	// back-channel logout alone. Nil means the default in
	// backchannelClient, whose timeout is measured; a test stands up an
	// httptest.NewServer and sets this so `go test` never touches a network it
	// did not create. See internal/oidc/channellogout.go.
	httpClient *http.Client
}

// realmBase is the URL every realm-scoped path hangs off, which the login
// form's action and the restart redirect both need to spell absolutely.
func (h *handler) realmBase(realm string) string {
	return h.issuerBase + "/realms/" + realm
}

// NewRouter wires the protocol endpoints served so far onto an
// http.ServeMux using Go 1.22 method-and-path patterns. issuerBase is the
// externally visible scheme://host[:port] the server is reachable at; every
// endpoint URL in the responses below is derived from it and the realm name
// at request time.
//
// The key manager is per server, not per realm: it resolves each realm's own
// persisted key set on demand. Passing a single realm's keys here was
// follow-up F5.
func NewRouter(s store.Store, k *keys.Manager, issuerBase string) http.Handler {
	mux := http.NewServeMux()
	Register(mux, s, k, issuerBase)
	return WithKeycloakFallbacks(mux)
}

// Register adds the protocol endpoints to an existing mux, so a server can
// serve them alongside another API on one mux and wrap the result once.
//
// One mux matters rather than two handlers chained: the fallback shapes below
// are decided by whether *any* route matched, and a second mux would answer
// its own 404 for a path the first one owns. There are two measured fallback
// bodies and adding a third would be a divergence.
func Register(mux *http.ServeMux, s store.Store, k *keys.Manager, issuerBase string) {
	h := &handler{store: s, keys: k, issuerBase: issuerBase,
		auth: newAuthStore(), device: newDeviceStore(), consents: newConsentStore(),
		registrations: newRegistrationStore(), proofs: newProofStore()}
	h.register(mux)
}

// register puts the routes on a mux. It is split out of Register so a test can
// hold the handler and its router at once, which is what the device grant's
// clock tests need: the poll interval and the expiry grace window are reached
// by moving a stored code, never by sleeping.
func (h *handler) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /realms/{realm}/.well-known/openid-configuration", h.discovery)
	// Both verbs, and they do not read the same place: GET takes its
	// parameters from the query and POST from the form body. See
	// authorizationParams.
	//
	// Keycloak answers PUT, DELETE and PATCH on this path with a real 405 and
	// application/json, where WithKeycloakFallbacks below sends the 404 it
	// sends for every other known path hit with the wrong method. That is the
	// third counter-example to "a wrong method is not always 404" and nothing
	// is changed on the strength of it; see follow-up F31.
	mux.HandleFunc("GET /realms/{realm}/protocol/openid-connect/auth", h.authorize)
	mux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/auth", h.authorize)
	// Both verbs again, and again they read different places: GET takes the
	// query and POST the body. Measured 2026-08-29, the same as /auth.
	//
	// Keycloak answers PUT, DELETE and PATCH here with a real 405 carrying
	// {"error":"HTTP 405 Method Not Allowed"}, and OPTIONS with a 200 that
	// has **no Allow header** - where /auth's OPTIONS sends
	// "Allow: HEAD, POST, GET, OPTIONS". Two neighbouring endpoints, one
	// container, two answers. That is the fourth data point in follow-up F31
	// and nothing here is changed on the strength of it.
	mux.HandleFunc("GET /realms/{realm}/protocol/openid-connect/logout", h.logout)
	mux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/logout", h.logout)
	// Both verbs, and unlike the two endpoints above they read the **same**
	// place for their five parameters - the query - while the credentials come
	// from the body alone. So a GET here is not a read: it attempts the login
	// with empty credentials and re-serves the page with "Invalid username or
	// password." and a rotated session_code, which is measured and which falls
	// out of reading the credentials from PostForm.
	//
	// Keycloak answers PUT, DELETE and PATCH here with a real 405, OPTIONS with
	// 200 and "Allow: HEAD, POST, GET, OPTIONS" - and **HEAD with a 404**, where
	// /auth's HEAD is a 200. Two endpoints in one flow, one container, opposite
	// answers to one verb. That is a sixth data point for follow-up F31 and
	// nothing here is changed on the strength of it: WithKeycloakFallbacks sends
	// its 404 to all of them.
	mux.HandleFunc("GET /realms/{realm}/login-actions/authenticate", h.loginActions)
	mux.HandleFunc("POST /realms/{realm}/login-actions/authenticate", h.loginActions)
	// The OAUTH_GRANT consent page and the two buttons on it. **GET on
	// /login-actions/consent is a 404**, measured
	// `{"error":"HTTP 404 Not Found"}`, which is what WithKeycloakFallbacks
	// already answers for a known path hit with the wrong method - so
	// registering POST alone is the measured behaviour rather than an omission.
	// **POST is registered here and not on /login-actions/consent's sibling**:
	// a required action's own form posts back to this path, where the consent
	// page posts to /login-actions/consent. Measured, and the two verbs answer
	// identically on all six cells of the session_code x execution grid.
	mux.HandleFunc("GET /realms/{realm}/login-actions/required-action", h.requiredAction)
	mux.HandleFunc("POST /realms/{realm}/login-actions/required-action", h.requiredAction)
	mux.HandleFunc("POST /realms/{realm}/login-actions/consent", h.consent)
	// **These two paths are one endpoint mounted twice**, measured in both
	// directions and on both verbs: POST on either mints a device code, GET on
	// either serves the verification page. Four probes per path, identical
	// answers. Registering the same two handlers on both is what reproduces it -
	// and it is also why the theme's own verification form cannot work, since it
	// posts `device_user_code` with no client_id and reaches the authorization
	// request. See httpx.WriteThemeDeviceCodePage.
	//
	// PUT, DELETE and PATCH answer a real 405 here, and OPTIONS answers 200
	// with **no Allow header** - which is /logout's answer and not /auth's.
	// That is another data point for follow-up F31 and nothing is changed on
	// the strength of it.
	mux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/auth/device", h.deviceAuthorization)
	mux.HandleFunc("GET /realms/{realm}/protocol/openid-connect/auth/device", h.deviceVerification)
	mux.HandleFunc("POST /realms/{realm}/device", h.deviceAuthorization)
	mux.HandleFunc("GET /realms/{realm}/device", h.deviceVerification)
	mux.HandleFunc("GET /realms/{realm}/device/status", h.deviceStatus)
	// CIBA's backchannel endpoint. Every answer it can give on a default
	// 26.7.1 is a refusal, including the 503 a fully valid request gets,
	// because the authentication channel a default deployment ships is not
	// configured. See internal/oidc/ciba.go.
	mux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/ext/ciba/auth", h.backchannelAuthentication)
	mux.HandleFunc("GET /realms/{realm}/protocol/openid-connect/certs", h.certs)
	mux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/token", h.token)
	mux.HandleFunc("GET /realms/{realm}/protocol/openid-connect/userinfo", h.userinfo)
	mux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/userinfo", h.userinfo)
	mux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/token/introspect", h.introspect)
	mux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/revoke", h.revoke)
	// The SAML IdP metadata descriptor. It is the one SAML response that is a
	// pure function of the realm and needs neither an assertion builder nor a
	// browser.
	mux.HandleFunc("GET /realms/{realm}/protocol/saml/descriptor", h.samlDescriptorEndpoint)
	// The SSO binding endpoint and the IdP-initiated route, both of which serve
	// their measured rejection ladders and neither of which serves its success
	// path - that needs a signed SAML assertion and there is no assertion
	// builder here. See internal/oidc/samlendpoint.go for the ladders and for
	// what a request that passes every rung is answered with, and
	// docs/superpowers/handover/p11-saml-sso.md for the measurements.
	//
	// **GET and POST are registered separately rather than as a bare pattern**,
	// because the other four verbs are not this endpoint's: PUT, DELETE and
	// PATCH answer a real 405 and OPTIONS a 200 with an Allow, all of which are
	// F31's standing divergence, and leaving them to protocolDispatch keeps
	// Gloak's answer to them exactly what it was.
	mux.HandleFunc("GET /realms/{realm}/protocol/saml", h.samlEndpoint)
	mux.HandleFunc("POST /realms/{realm}/protocol/saml", h.samlEndpoint)
	mux.HandleFunc("GET /realms/{realm}/protocol/saml/clients/{name}", h.samlIdPInitiated)
	// The protocol dispatcher. Three patterns and one handler, covering
	// everything under /realms/{realm}/protocol that no route above serves.
	// See protocolDispatch for what each of them answers and why.
	//
	// All methods, deliberately: `Protocol not found` was measured on GET,
	// POST, PUT, DELETE, OPTIONS and HEAD and is byte-identical on all six,
	// which no other route in this file can say.
	//
	// **{rest...} needs no sibling for the trailing-slash case.**
	// /protocol/x/ and /protocol/x/a/ reach WithKeycloakFallbacks first, which
	// strips the one trailing slash Keycloak strips, so they arrive here as
	// /protocol/x and /protocol/x/a. That is the order the two rules compose
	// in on a live 26.7.1 - normalise, then route - and it is the reason the
	// bare /realms/{realm}/protocol pattern below covers /protocol/ too.
	mux.HandleFunc("/realms/{realm}/protocol", h.protocolDispatch)
	mux.HandleFunc("/realms/{realm}/protocol/{protocol}", h.protocolDispatch)
	mux.HandleFunc("/realms/{realm}/protocol/{protocol}/{rest...}", h.protocolDispatch)
	// Dynamic client registration, the `openid-connect` provider.
	//
	// **Only that one provider is registered.** A default 26.7.1 serves four -
	// `default`, `install` and `saml2-entity-descriptor` beside it - and they
	// do not agree about verbs: `install` answers 405 to a POST and
	// `saml2-entity-descriptor` answers 405 to a GET. An unknown provider is
	// its own 404, `{"error":"Client registration provider not found"}`.
	// Registering a `{provider}` wildcard here would let Gloak send that
	// measured string for `default` and `install`, which exist - a measured
	// body for the wrong condition - so the three fall through to
	// WithKeycloakFallbacks instead and are filed as a divergence.
	//
	// The verbs on the paths that *are* registered were measured too:
	// GET, PUT and DELETE on the collection answer the same
	// `{"error":"HTTP 404 Not Found"}` WithKeycloakFallbacks already sends,
	// so three of the five agree by construction; PATCH and HEAD answer a real
	// 405, which is another pair for follow-up F31 and is not changed here.
	mux.HandleFunc("POST /realms/{realm}/clients-registrations/openid-connect", h.registerClient)
	mux.HandleFunc("GET /realms/{realm}/clients-registrations/openid-connect/{clientId}", h.readRegisteredClient)
	mux.HandleFunc("PUT /realms/{realm}/clients-registrations/openid-connect/{clientId}", h.updateRegisteredClient)
	mux.HandleFunc("DELETE /realms/{realm}/clients-registrations/openid-connect/{clientId}", h.deleteRegisteredClient)
	mux.HandleFunc("GET /realms/{realm}", h.realmInfo)
	// The realm resource dispatcher, F184. Two patterns and one handler,
	// covering everything under /realms/{realm} that no route serves -
	// including the routes internal/account and any later package put on this
	// same mux, which nothing here has to know about. See
	// realmResourceDispatch for the measurements.
	//
	// It is written last for a reader rather than for the router: ServeMux
	// gives a request to the most specific pattern that matches it, not to the
	// first one registered, so the two packages can register in either order.
	// TestTheRealmResourceDispatcherDoesNotSwallowAServedRoute is what checks
	// that, on a mux holding both.
	//
	// All methods, deliberately: the realm is resolved before the method is
	// dispatched on a live 26.7.1, so POST on a path only GET serves under an
	// unknown realm answers about the realm rather than about the method.
	//
	// **The bare pattern is not decoration.** Registering the {rest...} one
	// alone makes Go's ServeMux register an implicit redirect at
	// /realms/{realm}, and POST /realms/master then answers a 307 to
	// /realms/master/ - with a non-empty pattern, so WithKeycloakFallbacks
	// hands it to the mux and net/http writes its own HTML body. That is
	// F153's shape and §3.1's 301 hazard met again, verified by running the
	// route table rather than read from the documentation.
	//
	// **Neither pattern reaches /realms or /realms/.** A ServeMux wildcard
	// matches a non-empty segment, so {realm} does not match the empty one,
	// and both spellings stay off the route table - which is what Keycloak
	// measurably does with them. A catch-all one segment higher would take
	// that away.
	mux.HandleFunc("/realms/{realm}", h.realmResourceDispatch)
	mux.HandleFunc("/realms/{realm}/{rest...}", h.realmResourceDispatch)
}

// registeredProtocols is the set of login protocols a default Keycloak 26.7.1
// has registered, and it is a **contract rather than a list of what Gloak
// serves**: `saml` is in it although Gloak serves one SAML endpoint, because
// what decides the answer below is whether Keycloak's protocol map has the
// key, not whether anything is mounted under it.
//
// Measured 2026-09-07 by sweeping /realms/master/protocol/{name}. Two are
// registered; everything else answers `Protocol not found`, including
// `docker-v2` - the Docker registry protocol exists in Keycloak and its
// feature is off on a default start-dev, which is `CLIENT_TYPES`' situation
// and the same reason the constant is the contract. The comparison is
// **case-sensitive**: `SAML` and `OPENID-CONNECT` both answer
// `Protocol not found`, so a fold here would serve the wrong body for two
// spellings a caller really sends.
var registeredProtocols = map[string]bool{
	"openid-connect": true,
	"saml":           true,
}

// protocolDispatch answers every path under /realms/{realm}/protocol that no
// route above serves. It exists because Keycloak's answer there is decided by
// its protocol map and not by its route table, so the fallback cannot produce
// it: an unmatched path gets `Unable to find matching target resource method`
// with none of the five security headers, and every cell below carries all
// five.
//
// Measured 2026-09-07 on a live 26.7.1, all with the five security headers and
// no Cache-Control:
//
//	/realms/nosuchrealm/protocol/anything   404 {"error":"Realm does not exist"}
//	/realms/master/protocol                 404 {"error":"HTTP 404 Not Found"}
//	/realms/master/protocol/openid-connect  404 {"error":"HTTP 404 Not Found"}
//	/realms/master/protocol/oidc/certs      404 {"error":"Protocol not found"}
//	/realms/master/protocol/x/a/b/c/d       404 {"error":"Protocol not found"}
//
// Three things in that table are each one probe away from an implementation
// that looks right:
//
//   - **The realm is resolved first.** An unknown realm answers about the realm
//     even when the protocol is unknown too, so a dispatcher that checks the
//     protocol first is wrong on every request that gets both wrong.
//   - **A registered protocol stops the dispatch.**
//     /protocol/openid-connect/nosuchsub answers `HTTP 404 Not Found`, not
//     `Protocol not found`, at any depth - so the map is load-bearing and a
//     catch-all that answered one sentence everywhere would be wrong on every
//     mistyped OIDC path there is.
//   - **The bare /protocol segment is not a protocol.** It answers
//     `HTTP 404 Not Found` rather than `Protocol not found` for the empty name,
//     which is why the empty string is handled here and not by leaving it out
//     of registeredProtocols.
func (h *handler) protocolDispatch(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	protocol := r.PathValue("protocol")
	if protocol == "" || registeredProtocols[protocol] {
		httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
		return
	}
	httpx.WriteMessageError(w, http.StatusNotFound, "Protocol not found")
}

// realmResourceDispatch answers every path under /realms/{realm} that no route
// serves. It exists for protocolDispatch's reason one segment higher up: a
// request that names a realm reaches Keycloak's filter chain through the realm
// resource's own locator, so it carries all five security headers, where the
// fallback's unmatched-path body carries none of them.
//
// Measured 2026-09-09 on a live 26.7.1, all with the five security headers and
// no Cache-Control, `application/json`:
//
//	/realms/master/nosuchthing                 404 {"error":"HTTP 404 Not Found"}
//	/realms/master/nosuchthing/deeper          404 {"error":"HTTP 404 Not Found"}
//	/realms/master/nosuchthing/a/b/c/d/e       404 {"error":"HTTP 404 Not Found"}
//	/realms/master/login-actions/nosuchaction  404 {"error":"HTTP 404 Not Found"}
//	/realms/master/device/nosuchsub            404 {"error":"HTTP 404 Not Found"}
//	/realms/master/.well-known/nosuchdoc       404 {"error":"HTTP 404 Not Found"}
//	/realms/nosuchrealm/nosuchthing            404 {"error":"Realm does not exist"}
//	/realms/nosuchrealm/nosuchthing/deeper     404 {"error":"Realm does not exist"}
//
// Three things decide the shape and each of them is one probe away from an
// implementation that looks right:
//
//   - **The realm is resolved before the method is dispatched**, which is
//     stronger than protocolDispatch's "the realm is resolved first". POST on
//     /realms/nosuchrealm/.well-known/openid-configuration - a path this router
//     serves, hit with a method it does not - answers `Realm does not exist`
//     and not the wrong-method 404, and so does POST /realms/nosuchrealm. So
//     the patterns above carry no method: a GET-only catch-all would leave both
//     of those to WithKeycloakFallbacks, which cannot resolve a realm.
//   - **Depth changes nothing**, measured at one, two and six segments, so one
//     {rest...} pattern is the whole tree rather than a pattern per depth.
//   - **/realms and /realms/ are not part of it.** Both answer the
//     unmatched-path body with none of the five headers on a live 26.7.1 - the
//     one measured place where a shorter path is less reachable than a longer
//     one - so this dispatcher must not be registered a segment higher.
//
// Two families under /realms/{realm} answer something else and are **not**
// reproduced here, both measured on 2026-09-09 and both already divergences
// before this dispatcher existed:
//
//   - **/account runs its gate before it routes.** An unrouted account path is
//     401 for a caller with no token and this 404 only for one past the gate,
//     so this dispatcher is right on the authenticated cell and wrong on the
//     anonymous one. See account/dispatch/unknown-subpath-unauthenticated and
//     follow-up F209.
//   - **Keycloak content-negotiates this 404.** With `Accept: text/html` the
//     same path answers a 404 theme page instead of these thirty bytes. Gloak
//     does not parse Accept here. See follow-up F210.
func (h *handler) realmResourceDispatch(w http.ResponseWriter, r *http.Request) {
	if h.resolveRealm(w, r) == nil {
		return
	}
	httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
}

// WithKeycloakFallbacks routes requests that match no registered route, or
// match a route's path with the wrong method, through package httpx instead
// of falling through to net/http's own "404 page not found" and "Method Not
// Allowed" plain-text bodies - shapes no Keycloak client expects and which
// package httpx does not otherwise produce.
//
// Two path rules run ahead of the route table, in this order, because that is
// the order a live 26.7.1 applies them - normalise, then route.
//
// **A path that is not normalised never reaches a route.** A doubled slash, a
// "." segment or a ".." segment is a 400 that says so; see
// httpx.WriteNotNormalized for the measurement. That closes follow-up F11,
// which recorded that mux.Handler reports a non-empty pattern - the redirect
// handler's - for exactly these paths, so the guard below handed them to
// mux.ServeHTTP and net/http answered its own 307 with an HTML body. The
// guard now never sees them.
//
// **Exactly one trailing slash is stripped.** Measured 2026-09-07 across the
// whole server, which is F177's second question answered: it is not a protocol
// rule at all.
//
//	/realms/master/protocol/openid-connect/certs/   the endpoint's own 200
//	/realms/master/protocol/saml/descriptor/        the endpoint's own 200
//	/realms/master/protocol/openid-connect/auth/    auth's own 400 page
//	/realms/master/                                 the realm info 200
//	/realms/master/.well-known/openid-configuration/  discovery's own 200
//	/admin/realms/                                  the realm listing's 200
//	/admin/realms/master/clients/                   the client listing's 200
//	/admin/serverinfo/                              serverinfo's 200
//	/nosuchpath/                                    the unmatched-path 404
//	POST /realms/master/.well-known/openid-configuration/   the wrong-method 404
//
// The last two are what make this a strip rather than a route: the two
// fallback shapes answer a slashed path exactly as they answer the bare one,
// so nothing downstream needs to know the slash was there. **Two** trailing
// slashes are the 400 above rather than a second strip, which is why this
// trims one and never loops.
//
// It is done here rather than with a ServeMux subtree pattern per route
// because a subtree pattern changes what the *unslashed* path matches as well,
// and because net/http would then redirect the bare path with a 301 that
// Keycloak does not send.
//
// Both bodies are measured, recorded in
// internal/conformance/testdata/golden/http/fallback/ and written up in the
// "Fallback responses" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md. Keycloak
// answers a path matching no route with `{"error":"Unable to find matching
// target resource method"}`; it answers a known path hit with the wrong
// method the same way it answers every other unroutable request, its
// generic shape-2 404 (`{"error":"HTTP 404 Not Found"}`) - not 405, and
// with no `Allow` header.
//
// The five security headers (Referrer-Policy, Strict-Transport-Security,
// X-Content-Type-Options, X-Frame-Options, X-Robots-Tag) track the same
// split: present whenever a request reaches Keycloak's filter chain, which
// happens for a route match and for a known path hit with the wrong method,
// but not for a path matching no route at all. That is set here, at the
// point that distinguishes the two, rather than in package httpx.
func WithKeycloakFallbacks(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if notNormalized(r.URL.Path) {
			httpx.WriteNotNormalized(w)
			return
		}
		if p := r.URL.Path; len(p) > 1 && strings.HasSuffix(p, "/") {
			r = withPath(r, strings.TrimSuffix(p, "/"))
		}
		if _, pattern := mux.Handler(r); pattern == "" {
			// mux.Handler returns an empty pattern both when no route
			// matches the path and when a route matches the path but not
			// the method. Run the request against a throwaway response so
			// Go's own routing tells us which of the two happened, without
			// ever writing net/http's own body to the real client. Go's
			// ServeMux only ever sets an Allow header on the second case.
			probe := &fallbackProbe{}
			h, _ := mux.Handler(r)
			h.ServeHTTP(probe, r)

			if probe.header.Get("Allow") != "" {
				httpx.SetSecurityHeaders(w)
				httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
				return
			}
			httpx.WriteMessageError(w, http.StatusNotFound, "Unable to find matching target resource method")
			return
		}
		httpx.SetSecurityHeaders(w)
		mux.ServeHTTP(w, r)
	})
}

// notNormalized reports whether Keycloak refuses to route p at all: a doubled
// slash, or a "." or ".." segment. It reads the **decoded** path, which is what
// r.URL.Path holds, because the check on a live 26.7.1 fires for %2e and
// %2e%2e as well as for the literal characters.
//
// The root "/" is not a doubled slash and is deliberately not caught: Keycloak
// answers it a 302 to /admin/, which is a divergence this cut leaves alone
// rather than one this predicate should hide.
func notNormalized(p string) bool {
	if strings.Contains(p, "//") {
		return true
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// withPath returns a shallow copy of r whose URL path is p, so the stripped
// path is what the mux routes on and what handlers reading r.URL.Path see.
//
// It copies rather than mutating for http.StripPrefix's reason: the caller
// still owns r. RawPath is trimmed alongside Path so EscapedPath keeps using
// it - a trailing "/" is never a percent-escape, so trimming both leaves the
// two consistent, and clearing RawPath instead would re-escape a path that
// arrived with an escape in it.
func withPath(r *http.Request, p string) *http.Request {
	r2 := new(http.Request)
	*r2 = *r
	r2.URL = new(url.URL)
	*r2.URL = *r.URL
	r2.URL.Path = p
	r2.URL.RawPath = strings.TrimSuffix(r.URL.RawPath, "/")
	return r2
}

// fallbackProbe is a throwaway http.ResponseWriter used to learn whether
// net/http's default handling would have set an Allow header, without
// committing any of its output to the real client.
type fallbackProbe struct {
	header http.Header
}

func (p *fallbackProbe) Header() http.Header {
	if p.header == nil {
		p.header = make(http.Header)
	}
	return p.header
}

func (p *fallbackProbe) Write(b []byte) (int, error) { return len(b), nil }

func (p *fallbackProbe) WriteHeader(status int) {}

// resolveRealm looks up the realm named in the request path. On
// store.ErrNotFound it writes Keycloak's measured 404 shape and returns nil;
// callers must stop handling the request in that case. It returns the realm
// itself rather than its name because every endpoint past discovery needs its
// ID and its token lifespans.
func (h *handler) resolveRealm(w http.ResponseWriter, r *http.Request) *model.Realm {
	realm, err := h.store.Realms().ByName(r.Context(), r.PathValue("realm"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusNotFound, "Realm does not exist")
			return nil
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}
	return realm
}

// realmKeys resolves a realm's persisted key set, writing the 500 shape and
// returning nil when it cannot.
func (h *handler) realmKeys(w http.ResponseWriter, r *http.Request, realm *model.Realm) *keys.RealmKeys {
	k, err := h.keys.ForRealm(r.Context(), realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}
	return k
}

func (h *handler) discovery(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	// Measured on the golden: longer than every other endpoint's, and only
	// present on the 200 - the "realm does not exist" 404 above sends no
	// Cache-Control at all.
	w.Header().Set("Cache-Control", "no-cache, must-revalidate, no-transform, no-store")
	httpx.WriteJSON(w, http.StatusOK, discoveryDoc(h.issuerBase, realm.Name))
}

func (h *handler) certs(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSON(w, http.StatusOK, jwksFor(k))
}

// realmInfoDocument is Keycloak's public realm descriptor. Field order is
// measured: see the "Realm info endpoint" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md and
// internal/conformance/testdata/golden/realm/info/master.http.
type realmInfoDocument struct {
	Realm           string `json:"realm"`
	PublicKey       string `json:"public_key"`
	TokenService    string `json:"token-service"`
	AccountService  string `json:"account-service"`
	TokensNotBefore int    `json:"tokens-not-before"`
}

// realmInfo serves Keycloak's public realm descriptor: the realm name, its
// RSA public key in PKIX DER (base64, no PEM headers, matching what a live
// Keycloak 26.7.1 returns), the token service base and the account service
// URL.
func (h *handler) realmInfo(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}
	pub, err := publicKeyDER(k)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	realmBase := h.issuerBase + "/realms/" + realm.Name
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, realmInfoDocument{
		Realm:           realm.Name,
		PublicKey:       pub,
		TokenService:    realmBase + "/protocol/openid-connect",
		AccountService:  realmBase + "/account",
		TokensNotBefore: 0,
	})
}

// publicKeyDER returns the realm's RSA signing key encoded as base64 PKIX
// DER, the form Keycloak's realm info endpoint uses for public_key.
func publicKeyDER(k *keys.RealmKeys) (string, error) {
	set := k.JWKS()
	pub, ok := set.Keys[0].Key.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("oidc: signing key is not RSA")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

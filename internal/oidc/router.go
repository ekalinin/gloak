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
		auth: newAuthStore(), device: newDeviceStore(), consents: newConsentStore()}
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
	mux.HandleFunc("GET /realms/{realm}/login-actions/required-action", h.requiredAction)
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
	mux.HandleFunc("GET /realms/{realm}", h.realmInfo)
}

// WithKeycloakFallbacks routes requests that match no registered route, or
// match a route's path with the wrong method, through package httpx instead
// of falling through to net/http's own "404 page not found" and "Method Not
// Allowed" plain-text bodies - shapes no Keycloak client expects and which
// package httpx does not otherwise produce.
//
// This does not cover every path net/http answers on its own. mux.Handler
// reports a non-empty pattern - the redirect handler's - for a request whose
// path is not "clean" in ServeMux's sense: a doubled slash (//realms/master)
// or a "." or ".." element (/realms/master/../master). The guard below only
// distinguishes "no route" from "route, wrong method"; it treats a non-clean
// path the same as a route match and hands it to mux.ServeHTTP, which
// answers with net/http's own 307 and an HTML body, never reaching httpx.
// See follow-up F11 in docs/superpowers/specs/2026-08-18-gloak-followups.md
// - what Keycloak 26.7.1 itself answers for these paths has not been
// measured yet.
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

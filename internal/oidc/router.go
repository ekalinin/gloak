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
	"github.com/ekalinin/gloak/internal/store"
)

type handler struct {
	store      store.Store
	keys       *keys.RealmKeys
	issuerBase string
}

// NewRouter wires the protocol endpoints served so far onto an
// http.ServeMux using Go 1.22 method-and-path patterns. issuerBase is the
// externally visible scheme://host[:port] the server is reachable at; every
// endpoint URL in the responses below is derived from it and the realm name
// at request time.
func NewRouter(s store.Store, k *keys.RealmKeys, issuerBase string) http.Handler {
	mux := http.NewServeMux()
	h := &handler{store: s, keys: k, issuerBase: issuerBase}
	mux.HandleFunc("GET /realms/{realm}/.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("GET /realms/{realm}/protocol/openid-connect/certs", h.certs)
	mux.HandleFunc("GET /realms/{realm}", h.realmInfo)
	return withKeycloakFallbacks(mux)
}

// withKeycloakFallbacks routes requests that match no registered route, or
// match a route's path with the wrong method, through package httpx instead
// of falling through to net/http's own "404 page not found" and "Method Not
// Allowed" plain-text bodies - shapes no Keycloak client expects and which
// package httpx does not otherwise produce.
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
func withKeycloakFallbacks(mux *http.ServeMux) http.Handler {
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
				httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
				return
			}
			httpx.WriteMessageError(w, http.StatusNotFound, "Unable to find matching target resource method")
			return
		}
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
// store.ErrNotFound it writes Keycloak's measured 404 shape and returns
// false; callers must stop handling the request in that case.
func (h *handler) resolveRealm(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("realm")
	if _, err := h.store.Realms().ByName(r.Context(), name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusNotFound, "Realm does not exist")
			return "", false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return "", false
	}
	return name, true
}

func (h *handler) discovery(w http.ResponseWriter, r *http.Request) {
	realm, ok := h.resolveRealm(w, r)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, discoveryDoc(h.issuerBase, realm))
}

func (h *handler) certs(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.resolveRealm(w, r); !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, jwksFor(h.keys))
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
	realm, ok := h.resolveRealm(w, r)
	if !ok {
		return
	}
	pub, err := publicKeyDER(h.keys)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	realmBase := h.issuerBase + "/realms/" + realm
	httpx.WriteJSONCharset(w, http.StatusOK, realmInfoDocument{
		Realm:           realm,
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

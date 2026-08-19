// Package oidc serves the OpenID Connect protocol endpoints built so far:
// discovery, JWKS and the realm's public info endpoint. Token issuance and
// the browser flow are separate, later plans.
package oidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	return mux
}

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
	writeJSON(w, http.StatusOK, discoveryDoc(h.issuerBase, realm))
}

func (h *handler) certs(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.resolveRealm(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, h.keys.JWKS())
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
	writeJSON(w, http.StatusOK, map[string]any{
		"realm":             realm,
		"public_key":        pub,
		"token-service":     realmBase + "/protocol/openid-connect",
		"account-service":   realmBase + "/account",
		"tokens-not-before": 0,
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

// writeJSON writes a 200-path JSON body. Error responses always go through
// package httpx instead, which owns Keycloak's error shapes.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

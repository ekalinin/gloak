package oidc

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/token"
)

// userinfoDocument is the userinfo success body.
//
// **This shape is unmeasured.** No client on a bootstrapped master realm can
// produce a token userinfo accepts: admin-cli is the only one with direct
// access grants and it issues lightweight tokens, which this endpoint refuses
// outright. That is why oidc/userinfo/get-with-valid-token and
// post-with-valid-token have no golden and stay Pending. The fields below are
// the measured ID-token claim set narrowed to what userinfo is defined to
// return; whoever first creates a confidential client - P2 - has to record the
// real response and correct this.
type userinfoDocument struct {
	Sub               string `json:"sub"`
	EmailVerified     bool   `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email,omitempty"`
}

// userinfo serves GET and POST /realms/{realm}/protocol/openid-connect/userinfo.
//
// Four rejections are measured, and the order of the checks is measured with
// them: a lightweight token carrying the openid scope gets the lightweight
// refusal, while a lightweight token *without* it gets the scope refusal - so
// the scope check runs first. The goldens are under
// internal/conformance/testdata/golden/oidc/userinfo/.
func (h *handler) userinfo(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}

	// Measured on all four rejections: no-store, no-cache, and four of the
	// five security headers.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	httpx.SetUserinfoSecurityHeaders(w)

	raw := bearerToken(r)
	if raw == "" {
		// The bare challenge, with no error at all.
		httpx.WriteBearerChallenge(w, http.StatusUnauthorized, realm.Name, "", "")
		return
	}
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}

	parsed, err := token.ParseAccess(k, h.realmIssuer(realm.Name), raw, time.Now())
	if err != nil {
		httpx.WriteBearerChallenge(w, http.StatusUnauthorized, realm.Name,
			"invalid_token", "Token verification failed")
		return
	}
	if !hasScope(parsed.Scope, "openid") {
		httpx.WriteBearerChallenge(w, http.StatusForbidden, realm.Name,
			"insufficient_scope", "Missing openid scope")
		return
	}

	client, err := h.store.Clients().ByClientID(r.Context(), realm.ID, parsed.ClientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteBearerChallenge(w, http.StatusUnauthorized, realm.Name,
				"invalid_token", "Token verification failed")
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if token.IsLightweight(client) {
		httpx.WriteBearerChallenge(w, http.StatusUnauthorized, realm.Name,
			"invalid_token", "Lightweight access token not allowed for userinfo endpoint")
		return
	}

	user, err := h.userBehind(r, realm, parsed)
	if err != nil {
		httpx.WriteBearerChallenge(w, http.StatusUnauthorized, realm.Name,
			"invalid_token", "Token verification failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, userinfoDocument{
		Sub:               user.ID,
		EmailVerified:     user.EmailVerified,
		PreferredUsername: user.Username,
		Email:             user.Email,
	})
}

// userBehind resolves the account a token speaks for. It goes through the
// session rather than through sub, because sub is exactly the claim a
// lightweight token omits - the same reason the Admin API will have to resolve
// the caller from sid in P2.
func (h *handler) userBehind(r *http.Request, realm *model.Realm, parsed *token.Parsed) (*model.User, error) {
	session, err := h.store.Sessions().UserSessionByID(r.Context(), realm.ID, parsed.SessionID)
	if err != nil {
		return nil, err
	}
	return h.store.Users().ByID(r.Context(), realm.ID, session.UserID)
}

// bearerToken reads the access token from the Authorization header, falling
// back to the access_token form field, which is how the POST form of this
// endpoint carries it.
func bearerToken(r *http.Request) string {
	if header := r.Header.Get("Authorization"); header != "" {
		if after, ok := strings.CutPrefix(header, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
		return ""
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			return r.PostForm.Get("access_token")
		}
	}
	return ""
}

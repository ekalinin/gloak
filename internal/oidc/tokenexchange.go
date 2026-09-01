package oidc

import (
	"errors"
	"net/http"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/token"
)

// grantTokenExchange is RFC 8693's grant type, and **it works on a default
// 26.7.1**.
//
// That is not what the catalogue said. `GET /admin/serverinfo` on 26.7.1
// reports three separate features: `TOKEN_EXCHANGE` and
// `TOKEN_EXCHANGE_DELEGATION` are disabled previews, and
// `TOKEN_EXCHANGE_STANDARD_V2` is `"type":"DEFAULT"` and **enabled**. The
// disabled one is the legacy exchange; the standard one is this grant. A case
// filed as "a feature that must be explicitly enabled" was describing the
// feature that is not the one this grant type reaches.
const grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// The token types this grant names. Only the access token is accepted in either
// direction: asking for a refresh token back is refused by name.
const (
	tokenTypeAccess  = "urn:ietf:params:oauth:token-type:access_token"
	tokenTypeRefresh = "urn:ietf:params:oauth:token-type:refresh_token"
)

// The measured ladder, one refusal per row, each adjacency driven by a request
// wrong in two ways at once. Every one is a 400 `invalid_request`, which is
// itself worth noticing: the neighbouring grants use `invalid_grant` for most
// of theirs.
//
//  1. the client's attribute is off   Standard token exchange is not enabled for the requested client
//  2. subject_token absent            Parameter 'subject_token' required for standard token exchange
//  3. subject_token_type absent       Parameter 'subject_token_type' required for standard token exchange
//  4. subject_token_type not access   Parameter 'subject_token' supports access tokens only
//  5. requested_token_type refresh    requested_token_type unsupported
//  6. subject_token unverifiable      Invalid token
//
// Rows 2 and 3 are two spellings of one sentence and the parameter name is the
// only difference, which is what makes a single "missing parameter" helper
// wrong here: the description names the parameter *and* the feature.
const (
	descExchangeDisabled       = "Standard token exchange is not enabled for the requested client"
	descExchangeMissingSubject = "Parameter 'subject_token' required for standard token exchange"
	descExchangeMissingType    = "Parameter 'subject_token_type' required for standard token exchange"
	descExchangeAccessOnly     = "Parameter 'subject_token' supports access tokens only"
	descExchangeRequestedType  = "requested_token_type unsupported"
	descExchangeInvalidToken   = "Invalid token"
)

// exchangeResponse is this grant's success body, in the measured key order.
//
// **It is not the ordinary nine keys.** There is no refresh_token and no
// id_token, `refresh_expires_in` is 0 rather than absent - the same shape the
// client_credentials grant has - and there is an eighth key after `scope` that
// no other grant emits. Reusing tokenResponse and appending a field would put
// `issued_token_type` in the wrong place, because tokenResponse's `scope` is
// last.
type exchangeResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
	IssuedTokenType  string `json:"issued_token_type"`
}

// tokenExchangeGrant serves urn:ietf:params:oauth:grant-type:token-exchange.
//
// The exchanged token keeps the subject's **session**: its sid is the subject
// token's, so the response's session_state is the one the original grant
// minted rather than a new one. That is why nothing here starts a session.
func (h *handler) tokenExchangeGrant(w http.ResponseWriter, r *http.Request,
	realm *model.Realm, client *model.Client, k *keys.RealmKeys) {
	if client.Attributes[attrExchangeGrant] != "true" {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descExchangeDisabled)
		return
	}
	// Presence, not value: an empty subject_token= reaches the verification and
	// answers "Invalid token", where an absent one answers about the parameter.
	subject, present := r.PostForm["subject_token"]
	if !present {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descExchangeMissingSubject)
		return
	}
	subjectType, present := r.PostForm["subject_token_type"]
	if !present {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descExchangeMissingType)
		return
	}
	if subjectType[0] != tokenTypeAccess {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descExchangeAccessOnly)
		return
	}
	// The requested type is checked before the subject token is verified: a
	// request asking for a refresh token with a garbage subject answers about
	// the requested type.
	if requested := r.PostForm.Get("requested_token_type"); requested != "" && requested != tokenTypeAccess {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descExchangeRequestedType)
		return
	}

	parsed, err := token.ParseAccess(k, h.realmIssuer(realm.Name), subject[0], time.Now())
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descExchangeInvalidToken)
		return
	}
	ctx := r.Context()
	session, err := h.store.Sessions().UserSessionByID(ctx, realm.ID, parsed.SessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descExchangeInvalidToken)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	user, err := h.store.Users().ByID(ctx, realm.ID, session.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descExchangeInvalidToken)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// The scope comes from the subject token rather than from the request: an
	// exchange of a token granted "openid profile email" answers with those
	// three, and the request names no scope.
	scope := parsed.Scope
	realmRoles, clientRoles, err := h.tokenRoles(ctx, realm, user)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	accessLife := accessLifespan(realm, client)
	issuer := &token.Issuer{Keys: k, Issuer: h.realmIssuer(realm.Name)}
	set, err := issuer.Issue(token.Request{
		Client:      client,
		User:        user,
		UserSession: session,
		Scope:       scope,
		RealmRoles:  realmRoles,
		ClientRoles: clientRoles,
		AccessLife:  accessLife,
		RefreshLife: realm.RefreshTokenLifespan,
		// No id_token even when openid was granted: the measured body has no
		// such key on a subject token whose scope begins with openid.
		IncludeIDToken: false,
	})
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, exchangeResponse{
		AccessToken:      set.AccessToken,
		ExpiresIn:        int64(accessLife.Seconds()),
		RefreshExpiresIn: 0,
		TokenType:        "Bearer",
		NotBeforePolicy:  0,
		SessionState:     session.ID,
		Scope:            scope,
		IssuedTokenType:  tokenTypeAccess,
	})
}

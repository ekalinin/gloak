package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
)

// The `Client Initial Access` tag, all three of its operations.
//
// **The family is authorised out of the clients pair**, `view-clients` and
// `manage-clients` on the listing and `manage-clients` alone on the create and
// the delete. `view-realm` and `manage-realm` are 403 on all three, measured
// one role at a time - which is the client-scope family's answer and not the
// component family's next door, and this branch adds one of each.

// clientInitialAccessCreateBody is Keycloak's
// `ClientInitialAccessCreatePresentation`, and it is **not** the response's
// shape.
//
// Two fields, and the four the response carries beside them are each refused on
// the way in:
//
//	{"id":…}              400 Unrecognized field "id" at line 1 column 8.
//	{"token":…}           400 …
//	{"timestamp":…}       400 …
//	{"remainingCount":…}  400 …
//
// So a caller cannot round-trip a row through the create, which is the opposite
// of what most of this API allows and is why the decode is strict against this
// type rather than against the representation below.
type clientInitialAccessCreateBody struct {
	Expiration *int64 `json:"expiration"`
	Count      *int   `json:"count"`
}

// clientInitialAccessRepresentation is what the create's 201 serves, in the
// measured key order.
//
// **Token carries omitempty and that is the whole difference between the two
// serialisations.** The 201 has six keys and `GET /clients-initial-access` has
// five, because the token is minted once and never stored - so the listing has
// nothing to serve it from and Keycloak's listing does not serve it either.
type clientInitialAccessRepresentation struct {
	ID             string `json:"id"`
	Token          string `json:"token,omitempty"`
	Timestamp      int64  `json:"timestamp"`
	Expiration     int64  `json:"expiration"`
	Count          int    `json:"count"`
	RemainingCount int    `json:"remainingCount"`
}

func clientInitialAccessRepresentationOf(m *model.ClientInitialAccess, token string) clientInitialAccessRepresentation {
	return clientInitialAccessRepresentation{
		ID:             m.ID,
		Token:          token,
		Timestamp:      m.Timestamp,
		Expiration:     m.Expiration,
		Count:          m.Count,
		RemainingCount: m.RemainingCount,
	}
}

// The two defaults `{}` produces, measured: one registration and no expiry.
const (
	defaultInitialAccessCount      = 1
	defaultInitialAccessExpiration = 0
)

// typeInitialAccess is the token's `typ`. It is spelled here rather than in
// internal/token because this branch does not own that package; see F160, which
// also records that Gloak's own registration endpoint does not yet accept one.
const typeInitialAccess = "InitialAccessToken"

// initialAccessClaims is the token's payload in the measured key order, decoded
// off a live one on 2026-09-03:
//
//	{"exp":1788528414,"iat":1788528114,"jti":"1e402928-…",
//	 "iss":"http://localhost:8165/realms/probe-small",
//	 "aud":"http://localhost:8165/realms/probe-small","typ":"InitialAccessToken"}
//
// **`exp` is the literal 0 when the request asked for no expiry**, not an
// absent claim and not a far-future instant - the same shape the registration
// access token has, and the reason neither can go through token.check().
type initialAccessClaims struct {
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Typ string `json:"typ"`
}

// listClientInitialAccess serves GET /admin/realms/{realm}/clients-initial-access.
//
// **Insertion order**, which is measured rather than chosen: three rows created
// in one realm came back in creation order on two container starts and two
// reads apiece, and their ids are random UUIDs that do not sort that way. An
// exhausted row stays in the list at `remainingCount: 0`; nothing sweeps.
func (h *handler) listClientInitialAccess(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	rows, err := h.store.ClientInitialAccess().List(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := make([]clientInitialAccessRepresentation, 0, len(rows))
	for _, m := range rows {
		out = append(out, clientInitialAccessRepresentationOf(m, ""))
	}
	writeAdminJSON(w, out)
}

// createClientInitialAccess serves POST /admin/realms/{realm}/clients-initial-access.
//
// The order of its refusals, each measured with a request wrong in one way:
//
//	Content-Type not JSON     415  the shared @Consumes sentence
//	empty body or null        500  unknown_error / consult the server log
//	a body that is not JSON   400  Cannot parse the JSON, code by body shape
//	an unknown field          400  the strict decoder, with a line and column
//	count < 0                 400  {"error":"Invalid value for count", …}
//	expiration < 0            400  {"error":"Invalid value for expiration", …}
//
// **`count: 0` is a 201**, creating a token that can never be used, so the
// count check is a sign test and not a positivity one.
func (h *handler) createClientInitialAccess(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	body, ok := decodeClientInitialAccessBody(w, r)
	if !ok {
		return
	}
	count := defaultInitialAccessCount
	if body.Count != nil {
		count = *body.Count
	}
	expiration := int64(defaultInitialAccessExpiration)
	if body.Expiration != nil {
		expiration = *body.Expiration
	}
	// The two sentences differ in more than the field name - "The count" against
	// "The expiration time interval" - so they are two strings rather than one
	// with a substitution.
	if count < 0 {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "Invalid value for count",
			"The count cannot be less than 0")
		return
	}
	if expiration < 0 {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "Invalid value for expiration",
			"The expiration time interval cannot be less than 0")
		return
	}

	now := time.Now().UTC()
	m := &model.ClientInitialAccess{
		ID:             model.NewID(),
		RealmID:        rc.realm.ID,
		Timestamp:      now.Unix(),
		Expiration:     expiration,
		Count:          count,
		RemainingCount: count,
	}
	token, err := h.mintInitialAccessToken(r.Context(), rc, m, now)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.store.ClientInitialAccess().Create(r.Context(), m); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+
		"/clients-initial-access/"+m.ID)
	httpx.WriteJSONCharset(w, http.StatusCreated,
		clientInitialAccessRepresentationOf(m, token))
}

// deleteClientInitialAccess serves
// DELETE /admin/realms/{realm}/clients-initial-access/{id}.
//
// **204 for an id that does not exist**, and 204 again for one deleted twice -
// both measured, which is why there is no not-found branch here and why this
// chapter adds no spelling of not-found to the twenty-seven. It is the opposite
// of `DELETE /components/{id}` one route family away, whose repeat is a 404.
func (h *handler) deleteClientInitialAccess(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if err := h.store.ClientInitialAccess().Delete(r.Context(), rc.realm.ID,
		r.PathValue("initialAccessID")); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// decodeClientInitialAccessBody splits the empty body from the merely malformed
// one, the way the identity provider mapper create does and for the same
// measured reason: an empty body and a literal `null` are a 500 here where `{`
// is a 400.
func decodeClientInitialAccessBody(w http.ResponseWriter, r *http.Request) (*clientInitialAccessCreateBody, bool) {
	if !requireJSONBody(w, r) {
		return nil, false
	}
	var raw []byte
	if r.Body != nil {
		var err error
		raw, err = io.ReadAll(r.Body)
		if err != nil {
			writeClientInitialAccessConsultLog(w)
			return nil, false
		}
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || string(trimmed) == "null" {
		writeClientInitialAccessConsultLog(w)
		return nil, false
	}
	var body clientInitialAccessCreateBody
	if !decodeStrictBytes(w, raw, "ClientInitialAccessCreatePresentation", &body) {
		return nil, false
	}
	return &body, true
}

func writeClientInitialAccessConsultLog(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}

// mintInitialAccessToken signs the row's token with the realm's HMAC key.
//
// **It is minted here rather than in internal/token**, which every other token
// in this project comes from. That is a boundary this branch could not cross -
// it does not own that package - and it is filed as F160 together with the
// other half of the same gap: Gloak's own registration endpoint rejects the
// token this mints, because accepting it is a change to internal/oidc.
//
// `exp` is `iat + expiration` and **the literal 0 when the row has no expiry**,
// which is measured and is why the arithmetic cannot be a plain addition.
func (h *handler) mintInitialAccessToken(ctx context.Context, rc *reqContext,
	m *model.ClientInitialAccess, now time.Time) (string, error) {
	k, err := h.keys.ForRealm(ctx, rc.realm)
	if err != nil {
		return "", err
	}
	signer, err := k.HMACSigner()
	if err != nil {
		return "", err
	}
	issuer := h.issuerBase + "/realms/" + rc.realm.Name
	claims := initialAccessClaims{
		Iat: m.Timestamp,
		Jti: m.ID,
		Iss: issuer,
		Aud: issuer,
		Typ: typeInitialAccess,
	}
	if m.Expiration > 0 {
		claims.Exp = m.Timestamp + m.Expiration
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return signCompact(signer, payload)
}

func signCompact(signer jose.Signer, payload []byte) (string, error) {
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("admin: sign initial access token: %w", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("admin: serialise initial access token: %w", err)
	}
	return compact, nil
}

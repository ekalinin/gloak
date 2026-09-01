package oidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
)

// grantJWTBearer is RFC 7523's grant type.
//
// **Every answer it can give on a default 26.7.1 is a refusal, and the last one
// is a contract rather than a stub** - the same shape as CIBA's 503 and
// `client-types`' 501. The grant exchanges an assertion signed by an identity
// provider the realm trusts, and a default container has no identity providers;
// creating one is POST /admin/realms/{r}/identity-provider/instances, which
// Gloak does not serve, and the assertion would then have to be signed by a key
// that provider names.
//
// The gate is a client attribute, `oauth2.jwt.authorization.grant.enabled`, and
// finding it took a second sweep: six plausible spellings were tried and all
// six answered the refusal, and the real name turned up in the attributes
// **dynamic client registration writes** when a body names grant_types. Writing
// down "no client configuration opens it" after the first sweep would have been
// a correct observation with a wrong explanation attached.
const grantJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// The measured ladder, after the client authentication and the duplicated-key
// check that token() runs for every grant. Each adjacency was driven by a
// request wrong in two ways at once.
//
//  1. assertion absent            Missing parameter:assertion
//  2. assertion not a JWT         The provided assertion is not a valid JWT
//  3. a public client             Public client not allowed to use authorization grant
//  4. the attribute is off        JWT Authorization Grant is not supported for the requested client
//  5. no iss claim                Missing claim: iss
//  6. an iss naming no provider   No Identity Provider for provided issuer
//
// Row 1's spelling is the surprise: **`Missing parameter:assertion` has no
// space after the colon**, where every other missing-parameter description on
// this endpoint is `Missing parameter: x` and CIBA's is
// `missing parameter : login_hint` with a space on both sides. Three spellings
// of one phrase on one endpoint family.
//
// Rows 3 and 4 both precede row 5, measured: a public client sending an
// assertion with no iss is told about the client, and so is a confidential one
// whose attribute is off. So the assertion is parsed, then set aside while the
// client is judged, then read again.
const (
	descMissingAssertion   = "Missing parameter:assertion"
	descAssertionNotAJWT   = "The provided assertion is not a valid JWT"
	descPublicClientGrant  = "Public client not allowed to use authorization grant"
	descJWTGrantDisabled   = "JWT Authorization Grant is not supported for the requested client"
	descAssertionMissingIS = "Missing claim: iss"
	descNoIdentityProvider = "No Identity Provider for provided issuer"
)

// jwtBearerGrant serves urn:ietf:params:oauth:grant-type:jwt-bearer.
func (h *handler) jwtBearerGrant(w http.ResponseWriter, r *http.Request, client *model.Client) {
	// Presence, not value: an empty assertion= reaches the parse and answers
	// "not a valid JWT", where an absent one answers about the parameter.
	assertion, present := r.PostForm["assertion"]
	if !present {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descMissingAssertion)
		return
	}
	claims, ok := assertionClaims(assertion[0])
	if !ok {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descAssertionNotAJWT)
		return
	}
	if client.PublicClient {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descPublicClientGrant)
		return
	}
	if client.Attributes[attrJWTBearerGrant] != "true" {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descJWTGrantDisabled)
		return
	}
	if claims.Iss == "" {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descAssertionMissingIS)
		return
	}
	// The end of the road on a default deployment. Gloak has no identity
	// provider model at all, so this is unconditional rather than a lookup that
	// always misses - and it says so, because a lookup that cannot succeed reads
	// like an unfinished one.
	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descNoIdentityProvider)
}

// assertionIssuer is the one claim this grant reads before it gives up.
type assertionIssuer struct {
	Iss string `json:"iss"`
}

// assertionClaims decides whether an assertion is "a valid JWT" for this
// endpoint, and the predicate is **structural**: three dot-separated parts
// whose middle one is base64url of a JSON object. Nothing about the signature
// is checked here, and neither is exp.
//
// Measured on six assertions: `a.b.c`, a two-part and a four-part string are
// all refused; a three-part one whose payload is `{}` passes and is refused a
// step later for its missing iss; and one carrying an exp in the past passes
// all the way to the identity provider lookup, which is what says expiry is not
// checked in front of it.
func assertionClaims(raw string) (assertionIssuer, bool) {
	var claims assertionIssuer
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return claims, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, false
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, false
	}
	return claims, true
}

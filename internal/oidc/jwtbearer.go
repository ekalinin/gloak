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
//  6. no sub claim                Missing claim: sub
//  7. an iss naming no provider   No Identity Provider for provided issuer
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
//
// **Row 6 was found by a mutation, not by a probe.** The first sweep of this
// ladder always sent `sub` beside `iss`, so an assertion carrying only `iss`
// had never been issued and the rung between row 5 and row 7 was invisible.
// Both are checked before the identity provider is looked up: an unknown issuer
// with no `sub` answers about the `sub`.
const (
	descMissingAssertion    = "Missing parameter:assertion"
	descAssertionNotAJWT    = "The provided assertion is not a valid JWT"
	descPublicClientGrant   = "Public client not allowed to use authorization grant"
	descJWTGrantDisabled    = "JWT Authorization Grant is not supported for the requested client"
	descAssertionMissingIS  = "Missing claim: iss"
	descAssertionMissingSub = "Missing claim: sub"
	descNoIdentityProvider  = "No Identity Provider for provided issuer"
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
	if claims.Sub == "" {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descAssertionMissingSub)
		return
	}
	// The end of the road on a default deployment. Gloak has no identity
	// provider model at all, so this is unconditional rather than a lookup that
	// always misses - and it says so, because a lookup that cannot succeed reads
	// like an unfinished one.
	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descNoIdentityProvider)
}

// assertionClaims are the two claims this grant reads before it gives up.
type assertionClaimSet struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
}

// assertionClaims decides whether an assertion is "a valid JWT" for this
// endpoint. The predicate is **structural** - nothing about the signature is
// checked, and neither is exp - and it is not "exactly three parts", which is
// what the first version of this function said.
//
// Measured across thirteen assertions:
//
//	one part                                refused
//	**two parts, a JSON object payload      accepted**
//	three parts, a JSON object payload      accepted
//	three parts, an empty signature         accepted
//	four parts, five parts                  refused
//	an empty header part                    refused
//	an empty payload part                   refused
//	a payload that is not base64url         refused
//	a payload that is a JSON *array*        refused
//	`a.b.c`                                 refused - `b` is not JSON
//
// So a signature part is **optional** and an empty one is fine, while the two
// parts in front of it must both be there. The two-part row is the one the
// obvious implementation gets wrong, and it was found by a mutation rather than
// by a probe: every earlier probe of a short assertion also carried a payload
// that was not JSON, so the length check and the JSON check could not be told
// apart. See the mutation section of
// docs/superpowers/handover/p7-registration.md.
func assertionClaims(raw string) (assertionClaimSet, bool) {
	var claims assertionClaimSet
	parts := strings.Split(raw, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return claims, false
	}
	if parts[0] == "" || parts[1] == "" {
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

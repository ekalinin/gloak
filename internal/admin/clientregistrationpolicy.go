package admin

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
)

// clientRegistrationPoliciesJSON is the eight client registration policy
// providers, read off a live 26.7.1 on 2026-09-06 and stored verbatim - with
// **one** value removed, which is the whole point of this file's doc comment.
//
// `allowed-client-templates`' `allowed-client-scopes` property carries an
// `options` list that is **not a constant of the provider**: it is the realm's
// own client scope names plus the literal `openid`. Measured in both
// directions - creating a client scope made it appear in the list, and master
// and a realm created through `POST /admin/realms` answer the same sixteen
// names in **different orders**. So that one list is computed in
// listClientRegistrationPolicyProviders and everything else here is the wire
// bytes.
//
// The two neighbouring lists are the opposite and are stored: the eight
// provider ids and `allowed-protocol-mappers`' 39 mapper type names came back
// in the same order on both realms, so they are asserted in order rather than
// masked. A mask on either would be a mask that changes nothing.
//
//go:embed clientregistrationpolicies.json
var clientRegistrationPoliciesJSON []byte

// clientRegistrationPolicyProvider is one row of the listing.
//
// The key order is measured: `id`, `helpText`, `properties`, `metadata`.
// `metadata` is `{}` on all eight, which is what `struct{}` writes and what a
// `map` would write as `null` when nil. `properties` is `[]` on three of them
// and is therefore a slice that must stay non-nil, which is why the embedded
// file holds `[]` rather than omitting the key.
//
// The property object is `providerProperty`, the identity provider catalogue's,
// unchanged: the two endpoints serve Keycloak's one
// `ConfigPropertyRepresentation` and all five of the key orders measured there
// appear here too.
type clientRegistrationPolicyProvider struct {
	ID         string             `json:"id"`
	HelpText   string             `json:"helpText"`
	Properties []providerProperty `json:"properties"`
	Metadata   struct{}           `json:"metadata"`
}

var (
	clientRegistrationPoliciesOnce sync.Once
	clientRegistrationPolicies     []clientRegistrationPolicyProvider
	clientRegistrationPoliciesErr  error
)

// loadClientRegistrationPolicies decodes the embedded file once.
func loadClientRegistrationPolicies() ([]clientRegistrationPolicyProvider, error) {
	clientRegistrationPoliciesOnce.Do(func() {
		clientRegistrationPoliciesErr = json.Unmarshal(
			clientRegistrationPoliciesJSON, &clientRegistrationPolicies)
	})
	return clientRegistrationPolicies, clientRegistrationPoliciesErr
}

// allowedClientScopesProperty names the one property whose options are the
// realm's rather than the provider's.
const allowedClientScopesProperty = "allowed-client-scopes"

// openIDScopeOption is the sixteenth name in that list on a default install,
// where the realm has fifteen client scopes. It is not one of them - the
// realm's own `GET /client-scopes` returns fifteen and `openid` is not among
// them - so it is appended rather than read.
const openIDScopeOption = "openid"

// listClientRegistrationPolicyProviders serves
// GET /admin/realms/{realm}/client-registration-policy/providers.
//
// It is the whole `Client Registration Policy` tag: one operation, eight
// providers, 4427 bytes on a default master.
//
// **Its guard is the realm pair and no clients role reaches it.** Measured
// 2026-09-06 with a token minted per role, nineteen single `master-realm`
// admin roles plus a caller holding nothing, against `GET /clients` as a
// control known to differ in **both** directions:
//
//	                  GET /clients   this listing
//	view-realm             403            200
//	manage-realm           403            200
//	view-clients           200            403
//	manage-clients         200            403
//	query-clients          200            403
//	sixteen others         403            403
//
// So an endpoint the description tags `Client Registration Policy`, whose
// options list is made of client scopes, is authorised out of the **realm**
// role set. AGENTS.md records the client-scope family going the other way -
// routes the description tags `Realms Admin` authorised out of the clients set
// - so the tag fails to predict the guard here for a third time, and in the
// second direction.
//
// The four wrong verbs answer a **real 405**, `{"error":"HTTP 405 Method Not
// Allowed"}`, on all four. Gloak sends 404; see F31.
func (h *handler) listClientRegistrationPolicyProviders(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	providers, err := loadClientRegistrationPolicies()
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	scopes, err := h.store.ClientScopes().ListByRealm(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := make([]clientRegistrationPolicyProvider, len(providers))
	for i, p := range providers {
		out[i] = p
		out[i].Properties = withAllowedClientScopes(p.Properties, scopes)
	}
	writeAdminJSON(w, out)
}

// withAllowedClientScopes fills the one option list that follows the realm.
//
// It copies rather than writing through, because the decoded providers are a
// package-level value shared by every request and every realm: filling in place
// would make one realm's client scopes the answer served to the next.
func withAllowedClientScopes(props []providerProperty, scopes []*model.ClientScope) []providerProperty {
	out := make([]providerProperty, len(props))
	copy(out, props)
	for i := range out {
		if out[i].Name != allowedClientScopesProperty {
			continue
		}
		options := make([]string, 0, len(scopes)+1)
		for _, s := range scopes {
			options = append(options, s.Name)
		}
		out[i].Options = append(options, openIDScopeOption)
	}
	return out
}

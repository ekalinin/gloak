package account

import (
	"net/http"
	"slices"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
)

// accountGroupRepresentation is a group as the account API serves it, and it
// is a **seventh** shape of one resource: AGENTS.md counts six on the realm
// group family and this is none of them.
//
// The wire order is measured - id, name, path, parentId, subGroups - and two
// of the five keys are the interesting ones:
//
//   - `parentId` is present for a child and **absent** for a group at the top
//     of the realm, where the realm family's membership listing carries the
//     same rule and the organization family carries `parentId` always.
//   - `subGroups` is always `[]`. It is never populated on this route, so a
//     handler that walked the children would be wrong on every group that has
//     any, and there is no parameter that turns it on: briefRepresentation and
//     direct were both measured doing nothing at all here.
//
// The four keys this shape does **not** have are what stop it being the admin
// API's: no `access`, no `subGroupCount`, no `attributes`, no `clientRoles`.
type accountGroupRepresentation struct {
	ID        string                       `json:"id"`
	Name      string                       `json:"name"`
	Path      string                       `json:"path"`
	ParentID  string                       `json:"parentId,omitempty"`
	SubGroups []accountGroupRepresentation `json:"subGroups"`
}

// groups serves GET /realms/{realm}/account/groups: the groups the token's
// own subject is a **direct** member of.
//
// **Membership does not reach upwards**, measured on this route rather than
// inherited from the realm family that already records it: a user joined to a
// child alone answers one row, the child, and its parent is not in the list
// although the child's own `parentId` names it. Expanding the ancestry is the
// obvious implementation of "the groups I am in" and it is wrong.
//
// Its guard is `view-groups` or `manage-account`, measured one role at a time
// over all eight of the account client's roles: those two answer 200 and the
// other six answer 403. **`view-profile` is one of the six**, which is what
// stops this guard being shared with linked-accounts next door.
func (h *handler) groups(w http.ResponseWriter, r *http.Request) {
	s := h.resolve(w, r)
	if s == nil {
		return
	}
	if !s.hasAny(roleViewGroups, roleManageAccount) {
		writeForbidden(w)
		return
	}
	memberships, err := h.store.Groups().ListUserGroups(r.Context(), s.realm.ID, s.user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := make([]accountGroupRepresentation, 0, len(memberships))
	for _, g := range memberships {
		ancestry, err := h.store.Groups().Ancestry(r.Context(), s.realm.ID, g.ID)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out = append(out, accountGroupRepresentation{
			ID:       g.ID,
			Name:     g.Name,
			Path:     groupPath(ancestry),
			ParentID: g.ParentID,
			// Always the empty array, never nil: `subGroups` is present on
			// every measured row and a nil slice marshals to null.
			SubGroups: []accountGroupRepresentation{},
		})
	}
	writeAccountJSON(w, out)
}

// groupPath is a group's path: every name from the root down, each preceded by
// a slash. ancestry is nearest last, which is what GroupRepo.Ancestry returns.
//
// It is this package's own rather than internal/admin's, which is unexported
// there and would have to be exported to be shared. That is deliberate as well
// as convenient: the two APIs' group shapes differ in four keys, and a shared
// helper is the first step towards a shared serialiser, which AGENTS.md
// records going wrong on this very resource.
func groupPath(ancestry []*model.Group) string {
	var b strings.Builder
	for _, g := range ancestry {
		b.WriteByte('/')
		b.WriteString(g.Name)
	}
	return b.String()
}

// linkedAccountRepresentation is one row of the linked-accounts listing. The
// wire order is measured: connected, providerAlias, providerName, displayName,
// social.
//
// `providerName` is the **alias**, not the provider id - measured on all
// fifteen listed providers, where the alias and the provider id differed on
// every one of them. Serving the provider id there is the obvious reading of
// the name and is wrong on every row.
type linkedAccountRepresentation struct {
	Connected     bool   `json:"connected"`
	ProviderAlias string `json:"providerAlias"`
	ProviderName  string `json:"providerName"`
	DisplayName   string `json:"displayName"`
	Social        bool   `json:"social"`
}

// socialProviderNames is the set of identity provider ids the account API
// marks `"social": true`, and the display name each of them carries when the
// provider itself has none.
//
// **The two facts are one fact and that is measured, not assumed.** Fifteen
// providers were created in one realm with no `displayName` at all and the
// listing read back: the eleven below came back `"social": true` **and**
// carrying one of these names, and `oidc`, `saml` and `keycloak-oidc` came back
// `"social": false` and carrying their **alias**. So a social provider has a
// declared name and a non-social one has none, and one table answers both
// questions rather than a set and a second lookup that could disagree.
//
// **No rule generates these names**, which is why they are transcribed rather
// than derived. Seven of the eleven defeat any case transformation:
//
//	bitbucket                BitBucket        a capital in the middle
//	github                   GitHub
//	gitlab                   GitLab
//	linkedin-openid-connect  LinkedIn         the suffix is dropped entirely
//	openshift-v4             Openshift v4     lower-case v, and **not** OpenShift
//	paypal                   PayPal
//	stackoverflow            StackOverflow
//
// A title-caser gets all seven wrong and the other four right, which is the
// shape a small sample hides: `Facebook`, `Google`, `Microsoft` and `Twitter`
// are exactly what capitalising the id gives.
//
// The eleven are also AGENTS.md's "eleven social providers", counted there from
// the `types` derivation on the Admin API. Two independent readings, one
// membership. That agreement is worth recording and is **not** a substitute for
// this table: `types` is `[]` for `oauth2` and `jwt-authorization-grant` too, so
// the predicate a reader would take from that sentence admits two providers this
// API does not call social.
var socialProviderNames = map[string]string{
	"bitbucket":               "BitBucket",
	"facebook":                "Facebook",
	"github":                  "GitHub",
	"gitlab":                  "GitLab",
	"google":                  "Google",
	"linkedin-openid-connect": "LinkedIn",
	"microsoft":               "Microsoft",
	"openshift-v4":            "Openshift v4",
	"paypal":                  "PayPal",
	"stackoverflow":           "StackOverflow",
	"twitter":                 "Twitter",
}

// unlistedProviderIDs are the two provider ids the linked-accounts listing
// leaves out even when the provider is enabled: `kubernetes` and
// `jwt-authorization-grant`.
//
// **Nothing observable here explains it and no hypothesis is encoded.** The
// obvious one is `hideOnLogin`, which a `kubernetes` create sets to true by
// default - and the pair itself refutes it, because a
// `jwt-authorization-grant` create sets nothing and is absent too. Both were
// confirmed present and `enabled: true` in the realm's own identity provider
// listing while absent from this one, so the filter is not `enabled` either.
// The table records what was measured; F193 is the entry that asks why.
var unlistedProviderIDs = map[string]bool{
	"jwt-authorization-grant": true,
	"kubernetes":              true,
}

// linkedAccounts serves GET /realms/{realm}/account/linked-accounts: the
// realm's identity providers a user could link to, with whether this user has.
//
// Three measured rules, each with the implementation it rules out:
//
//   - **Sorted by alias**, not by display name. A provider aliased `zzz-probe`
//     carrying the display name `AAA First` comes **last**, which is the row
//     that separates the two orderings; four providers created in a scrambled
//     order came back alphabetical by alias.
//   - **A disabled provider is absent and a link-only one is present.** So the
//     filter is `enabled` and not "can a user reach it from the login page",
//     which `linkOnly` would also answer.
//   - **`displayName` falls back to the provider's own name and only then to
//     the alias**, so the key is never empty. A `google` provider created with
//     no display name comes back `"Google"`, and an `oidc` one comes back
//     carrying its alias - see socialProviderNames. This was **wrong here
//     until the golden refuted it**: the first version fell back to the alias
//     for everything, which is right on the four non-social providers and
//     wrong on all eleven social ones, and every hand probe of this route had
//     used an `oidc` provider.
//
// It sends **no `Cache-Control` at all**, where the groups read one route away
// sends `no-cache`. Two neighbouring reads on one API, opposite answers, which
// is why this handler writes its own headers instead of calling
// writeAccountJSON.
//
// Its guard is `view-profile` or `manage-account`. **`manage-account-links` is
// refused**, measured, although it is the one account role whose name matches
// this route - so the role a reader reaches for first is the one that does not
// work, and a guard written from the name alone is wrong in both directions.
func (h *handler) linkedAccounts(w http.ResponseWriter, r *http.Request) {
	s := h.resolve(w, r)
	if s == nil {
		return
	}
	if !s.hasAny(roleViewProfile, roleManageAccount) {
		writeForbidden(w)
		return
	}
	providers, err := h.store.IdentityProviders().List(r.Context(), s.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := make([]linkedAccountRepresentation, 0, len(providers))
	for _, p := range providers {
		if !p.Enabled || unlistedProviderIDs[p.ProviderID] {
			continue
		}
		alias := ""
		if p.Alias != nil {
			alias = *p.Alias
		}
		socialName, social := socialProviderNames[p.ProviderID]
		// The provider's own display name wins over both - measured, a `google`
		// provider carrying "A Display" serves that and not "Google".
		display := p.DisplayName
		switch {
		case display != "":
		case socialName != "":
			display = socialName
		default:
			display = alias
		}
		out = append(out, linkedAccountRepresentation{
			// Connected is false for every row Gloak can serve: a federated
			// identity link is stored by internal/admin and nothing in this
			// package reads one yet, so a case pinning `"connected": true` is
			// out of reach. The catalogue says so rather than the field
			// pretending otherwise; see account/linked-accounts in the handover.
			Connected:     false,
			ProviderAlias: alias,
			ProviderName:  alias,
			DisplayName:   display,
			Social:        social,
		})
	}
	// IdentityProviderRepo.List already sorts by alias and the admin API's own
	// listing rests on that, but this route's order is its own measurement and
	// the sort is repeated here rather than inherited: a store that changed its
	// ORDER BY for the admin listing's sake would otherwise move this body with
	// nothing in this package saying it had an order at all.
	slices.SortFunc(out, func(a, b linkedAccountRepresentation) int {
		return strings.Compare(a.ProviderAlias, b.ProviderAlias)
	})
	httpx.WriteJSONCharset(w, http.StatusOK, out)
}

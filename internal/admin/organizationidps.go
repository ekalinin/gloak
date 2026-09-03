package admin

import (
	"errors"
	"io"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The organization identity provider family: five operations over a **column on
// the provider**, not a join table.
//
// Both directions are measured. Associating a provider through
// `POST /organizations/{org}/identity-providers` makes the realm's own read -
// `GET /identity-provider/instances/{alias}`, a different route in a different
// chapter - start carrying `"organizationId"`, and the delete drops the key and
// leaves the provider itself alone. So the bodies these routes serve are the
// identity provider chapter's bodies unchanged, and this file adds no
// serialiser.

// listOrganizationIdentityProviders serves
// GET /organizations/{org-id}/identity-providers.
func (h *handler) listOrganizationIdentityProviders(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	providers, err := h.store.IdentityProviders().ListByOrganization(r.Context(), rc.realm.ID, o.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := make([]identityProviderRepresentation, 0, len(providers))
	for _, p := range providers {
		out = append(out, identityProviderRepresentationOf(p, false))
	}
	writeAdminJSON(w, out)
}

// readOrganizationIdentityProvider serves
// GET /organizations/{org-id}/identity-providers/{alias}.
//
// Its body is byte-identical to the realm's own read of the same provider,
// `organizationId` included.
func (h *handler) readOrganizationIdentityProvider(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	p, ok := h.organizationIdentityProviderFromPath(w, r, rc, o)
	if !ok {
		return
	}
	writeAdminJSON(w, identityProviderRepresentationOf(p, false))
}

// listOrganizationIdentityProviderGroups serves
// GET /organizations/{org-id}/identity-providers/{alias}/groups.
//
// **It is always an empty array**, for listOrganizationMemberGroups' reason:
// the groups it answers are the organization's own, which are F120's eleven
// blocked operations, and no organization group can exist here. It resolves the
// association first, so an alias not associated with this organization is the
// same 404 the single read answers.
func (h *handler) listOrganizationIdentityProviderGroups(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	if _, ok := h.organizationIdentityProviderFromPath(w, r, rc, o); !ok {
		return
	}
	writeAdminJSON(w, []struct{}{})
}

// addOrganizationIdentityProvider serves
// POST /organizations/{org-id}/identity-providers.
//
// **It is a 204 with no Location**, where `POST .../members` in the same family
// is a 201 with one. Two adds on one resource, two statuses.
//
// The body is the alias, read the same way `POST .../members` reads a user id -
// raw, with the quotes trimmed - and the Content-Type is enforced: none at all
// is a 415, like the member add and unlike the two invite endpoints.
//
// Its three refusals are three different sentences and two different statuses:
//
//	an alias that resolves to nothing   400 "Identity provider not found with the given alias"
//	an alias already on this org        409 "Identity provider already associated to the organization"
//	an alias on another organization    400 "Identity provider already associated with a different organization"
//
// The 409 and the second 400 differ by one preposition, `to` against `with`.
// An empty body takes the first branch, because "" resolves to nothing.
func (h *handler) addOrganizationIdentityProvider(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	if !requireJSONContentType(w, r) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	alias := organizationMemberID(body)
	p, err := h.store.IdentityProviders().ByAlias(r.Context(), rc.realm.ID, alias)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeOrganizationIdentityProviderMissing(w, http.StatusBadRequest)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	switch p.OrganizationID {
	case o.ID:
		httpx.WriteAdminError(w, http.StatusConflict,
			"Identity provider already associated to the organization")
		return
	case "":
	default:
		httpx.WriteAdminError(w, http.StatusBadRequest,
			"Identity provider already associated with a different organization")
		return
	}
	if err := h.store.IdentityProviders().SetOrganization(r.Context(), rc.realm.ID, alias, o.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// removeOrganizationIdentityProvider serves
// DELETE /organizations/{org-id}/identity-providers/{alias}.
//
// **Its 404 is not the read's**, which is the finding: the same missing
// association answers `Identity provider not found with the given alias` here
// and `Identity provider not associated with the organization` on the two
// reads, measured on one alias in one session. One helper for the family would
// get one of the two wrong.
//
// It removes the association and leaves the provider.
func (h *handler) removeOrganizationIdentityProvider(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	alias := r.PathValue("idpAlias")
	p, err := h.store.IdentityProviders().ByAlias(r.Context(), rc.realm.ID, alias)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeOrganizationIdentityProviderMissing(w, http.StatusNotFound)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if p.OrganizationID != o.ID {
		writeOrganizationIdentityProviderMissing(w, http.StatusNotFound)
		return
	}
	if err := h.store.IdentityProviders().SetOrganization(r.Context(), rc.realm.ID, alias, ""); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// organizationIdentityProviderFromPath resolves the `{alias}` of the two reads.
//
// A provider that does not exist and one that exists and belongs to another
// organization answer the **same** sentence here - `Identity provider not
// associated with the organization` - which is the read's sentence and not the
// delete's.
func (h *handler) organizationIdentityProviderFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) (*model.IdentityProvider, bool) {
	p, err := h.store.IdentityProviders().ByAlias(r.Context(), rc.realm.ID, r.PathValue("idpAlias"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeOrganizationIdentityProviderUnassociated(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	if p.OrganizationID != o.ID {
		writeOrganizationIdentityProviderUnassociated(w)
		return nil, false
	}
	return p, true
}

// writeOrganizationIdentityProviderUnassociated is the reads' 404.
func writeOrganizationIdentityProviderUnassociated(w http.ResponseWriter) {
	httpx.WriteAdminError(w, http.StatusNotFound,
		"Identity provider not associated with the organization")
}

// writeOrganizationIdentityProviderMissing is the other sentence, and it
// reaches the wire under **two** statuses: 404 from the delete and 400 from the
// create. Same words, two statuses, two verbs.
func writeOrganizationIdentityProviderMissing(w http.ResponseWriter, status int) {
	httpx.WriteAdminError(w, status, "Identity provider not found with the given alias")
}

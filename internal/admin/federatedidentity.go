package admin

import (
	"errors"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The three operations under `/users/{user-id}/federated-identity`, and the
// thing to know about them before reading any of it:
//
// **A link may exist and be invisible.** Measured 2026-09-05 on a live 26.7.1,
// in this order, each step a separate request:
//
//	POST   .../federated-identity/nosuchidp   {"identityProvider":…}  204
//	GET    .../federated-identity                                     200 []
//	POST   .../federated-identity/nosuchidp   (the same body)         409
//	register an identity provider with alias nosuchidp                201
//	GET    .../federated-identity                                     200 [the link]
//
// The write does not check the alias and the read filters on it. The
// registration in the fourth step touches nothing about the link and changes
// what the second step answers, which is the control that says the filter is
// the read's and not the write's.
//
// So `LinkFederatedIdentity` stores whatever alias the path carried and
// `listFederatedIdentities` drops the rows whose alias the realm has no
// provider for. Moving the check to the write - which is the tidy version, and
// the one a reviewer will ask for - turns a measured 204 into a 404.
//
// Three more measurements the handlers below encode:
//
//   - **The path's `{provider}` wins over the body's `identityProvider`.** A
//     `POST` to `.../federated-identity/fi1` carrying
//     `{"identityProvider":"OTHER"}` stored and echoed `fi1`.
//   - **The body is decoded strictly.** An unknown field answers
//     `Invalid json representation for FederatedIdentityRepresentation.
//     Unrecognized field "bogus" at line 1 column 24.`, which makes this the
//     **fifth** strict endpoint rather than the fourth `strictjson.go` records.
//     A malformed body falls through to the ordinary `Cannot parse the JSON`
//     and a `text/plain` Content-Type is the 415.
//   - **No body at all is a 500**, `unknown_error`, the same Keycloak defect as
//     an empty body on `POST /users`.

// federatedIdentityRepresentation is Keycloak's
// FederatedIdentityRepresentation, in the measured field order.
//
// Both `userId` and `userName` carry omitempty because a `POST` with the body
// `{}` is a measured 204 whose row reads back as `{"identityProvider":"fi2"}` -
// one key, not three. `identityProvider` never does: it is the path's value and
// the path always has one.
type federatedIdentityRepresentation struct {
	IdentityProvider string `json:"identityProvider"`
	UserID           string `json:"userId,omitempty"`
	UserName         string `json:"userName,omitempty"`
}

// listFederatedIdentities serves
// GET /admin/realms/{realm}/users/{user-id}/federated-identity.
//
// 200 with `Cache-Control: no-cache`, `[]` for a user with no visible link, and
// the rows in **insertion order** - which is why the store carries a sequence
// column rather than ordering by alias.
func (h *handler) listFederatedIdentities(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	links, err := h.store.Users().ListFederatedIdentities(r.Context(), rc.realm.ID, user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := []federatedIdentityRepresentation{}
	for _, l := range links {
		// Existence alone decides visibility. A **disabled** provider was not
		// part of the measurement and no probe reached one, so this asks
		// whether the realm has a provider by that alias and nothing about its
		// `enabled` flag.
		switch _, err := h.store.IdentityProviders().ByAlias(r.Context(), rc.realm.ID, l.IdentityProvider); {
		case errors.Is(err, store.ErrNotFound):
			continue
		case err != nil:
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out = append(out, federatedIdentityRepresentation{
			IdentityProvider: l.IdentityProvider,
			UserID:           l.UserID,
			UserName:         l.Username,
		})
	}
	writeAdminJSON(w, out)
}

// addFederatedIdentity serves
// POST /admin/realms/{realm}/users/{user-id}/federated-identity/{provider}.
//
// 204 with `Cache-Control: no-cache`, and `X-Frame-Options` because the request
// declared an `application/*` Content-Type - the rule httpx.WriteNoContent
// already applies.
//
// The 409's body is `{"errorMessage":"User is already linked with provider"}`,
// which is the admin shape rather than the `Duplicate resource error` the other
// conflicts in this API answer, and it does not name the provider.
func (h *handler) addFederatedIdentity(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	if r.ContentLength == 0 {
		writeUserUnknownError(w)
		return
	}
	var rep federatedIdentityRepresentation
	if !decodeStrict(w, r, "FederatedIdentityRepresentation", &rep) {
		return
	}
	// The path wins. rep.IdentityProvider is decoded so that naming it is not
	// an unknown field, and then discarded.
	err := h.store.Users().LinkFederatedIdentity(r.Context(), rc.realm.ID, user.ID,
		model.FederatedIdentity{
			IdentityProvider: r.PathValue("provider"),
			UserID:           rep.UserID,
			Username:         rep.UserName,
		})
	switch {
	case errors.Is(err, store.ErrConflict):
		httpx.WriteAdminError(w, http.StatusConflict, "User is already linked with provider")
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// removeFederatedIdentity serves
// DELETE /admin/realms/{realm}/users/{user-id}/federated-identity/{provider}.
//
// 204 with `Cache-Control: no-cache` and **no** `X-Frame-Options`, the request
// carrying no Content-Type.
//
// A link that is not there is a real `404 {"error":"Link not found"}` - the
// thirty-sixth spelling of not-found in this API - rather than the silent 204
// the client-scope detaches answer. It deletes a link the listing cannot show,
// which is the other half of the invisible-link finding.
func (h *handler) removeFederatedIdentity(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	err := h.store.Users().UnlinkFederatedIdentity(r.Context(), rc.realm.ID, user.ID,
		r.PathValue("provider"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.WriteMessageError(w, http.StatusNotFound, "Link not found")
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

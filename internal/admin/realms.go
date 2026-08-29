package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The five operations of the Realms Admin tag that address the realm itself.
// See docs/superpowers/specs/2026-08-29-p4-multi-realm-design.md and the
// "Realms" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.

// listRealms serves GET /admin/realms.
//
// **Two things about it are not what a listing usually does.** It defaults to
// the *full* representation - briefRepresentation defaults to false here, the
// opposite of the role listings - and it renders each entry at the level the
// caller may see that realm, so one response can carry a 104-key object beside
// a one-key one.
//
// A caller that may see no realm at all gets 403 rather than an empty array,
// measured on a caller holding only the realm role create-realm, which gets 200
// on the single read of every realm and 403 here. The collection's two verbs
// disagree about who may use them in both directions: create-realm is also the
// only role POST accepts.
func (h *handler) listRealms(w http.ResponseWriter, r *http.Request, c *caller) {
	realms, err := h.store.Realms().List(r.Context())
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	brief := r.URL.Query().Get("briefRepresentation") == "true"
	out := make([]any, 0, len(realms))
	for _, realm := range realms {
		names, err := h.namesOnContainerFor(r.Context(), c, realm.Name)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if !opensARealm(names) {
			continue
		}
		entry, err := h.listingEntry(r.Context(), realm, names, brief)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		writeForbidden(w)
		return
	}
	writeAdminJSON(w, out)
}

// listingEntry is one row of the listing, and there are three of them.
//
// A caller that may view the realm gets the full representation, or the
// three-key brief one when it asked for it. Every other caller gets a **one-key**
// entry - narrower than the four-key body the same caller gets from the single
// read of the same realm - and briefRepresentation does nothing to it: absent
// and true were measured giving byte-identical bodies. One parameter, three
// answers.
func (h *handler) listingEntry(ctx context.Context, realm *model.Realm, names map[string]bool, brief bool) (any, error) {
	if !mayViewRealm(names) {
		return realmNarrowRepresentation{Realm: realm.Name}, nil
	}
	rep, err := h.realmRepresentationOf(ctx, realm)
	if err != nil {
		return nil, err
	}
	if brief {
		return realmBriefRepresentation{
			ID:              rep.ID,
			Realm:           rep.Realm,
			DisplayName:     rep.DisplayName,
			DisplayNameHTML: rep.DisplayNameHTML,
			Enabled:         rep.Enabled,
		}, nil
	}
	return rep, nil
}

// readRealm serves GET /admin/realms/{realm}, in whichever of the three shapes
// the caller has earned.
//
// **A weaker caller gets a shorter body, not a 403.** Sixteen of the
// twenty-one admin roles get four keys, view-users and manage-users get five -
// the extra one being registrationEmailAsUsername - and only view-realm,
// manage-realm and realm-admin get the whole thing.
func (h *handler) readRealm(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if !mayViewRealm(rc.caller.adminGrants) {
		writeAdminJSON(w, reducedRealm(rc.realm, rc.caller.adminGrants))
		return
	}
	rep, err := h.realmRepresentationOf(r.Context(), rc.realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, rep)
}

// reducedRealm builds the four- or five-key body from the realm row alone. It
// reads none of the settings blob on purpose: every key in it is either on the
// row or a constant.
//
// supportedLocales is `[]` here and **absent** from the full representation,
// which is why the two are different structs rather than one with a flag.
func reducedRealm(realm *model.Realm, names map[string]bool) realmReducedRepresentation {
	rep := realmReducedRepresentation{Realm: realm.Name, SupportedLocales: []string{}}
	if names["view-users"] || names["manage-users"] {
		// The one key that separates the two shapes. False is its measured
		// value, which is why the field is a pointer: omitempty would drop it.
		rep.RegistrationEmailAsUsername = ptr(false)
	}
	if full, err := decodeRealmSettings(realm); err == nil {
		rep.DisplayName = full.DisplayName
		rep.DisplayNameHTML = full.DisplayNameHTML
		rep.BruteForceProtected = full.BruteForceProtected
		rep.OrganizationsEnabled = full.OrganizationsEnabled
		if rep.RegistrationEmailAsUsername != nil {
			rep.RegistrationEmailAsUsername = ptr(full.RegistrationEmailAsUsername)
		}
	}
	return rep
}

// createRealm serves POST /admin/realms.
//
// It answers 201 with an empty body and a Location naming the **realm**, not
// the id - even when the body supplied one, which it may: a create carrying an
// id was measured producing a realm with exactly that id.
//
// **The realm it creates is disabled** unless the body says otherwise. `enabled`
// has no default, so a client that omits it gets a realm nobody can log into,
// and that is the measured behaviour rather than an oversight to correct.
func (h *handler) createRealm(w http.ResponseWriter, r *http.Request, c *caller) {
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		writeRealmStreamError(w)
		return
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		writeRealmStreamError(w)
		return
	}

	var named struct {
		ID    string `json:"id"`
		Realm string `json:"realm"`
	}
	_ = json.Unmarshal(body, &named)
	if named.Realm == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Realm name cannot be empty")
		return
	}

	rep := defaultRealmRepresentation(named.Realm)
	// On create the body's attributes **merge** with the defaults - measured, a
	// create carrying {"custom":"yes"} came back with all eight defaults and
	// custom - which is the opposite of what a PUT does to the same field.
	// Unmarshalling into a non-nil map is exactly that merge, so create needs
	// no special handling where update does.
	if err := applyRealmFields(&rep, fields); err != nil {
		writeRealmStreamError(w)
		return
	}

	realm := &model.Realm{
		ID:      named.ID,
		Name:    named.Realm,
		Enabled: rep.Enabled,
	}
	if realm.ID == "" {
		realm.ID = model.NewID()
	}
	applyLifespans(realm, &rep)
	realm.Settings = marshalRealmSettings(&rep)

	created, err := bootstrap.CreateRealm(r.Context(), h.store, named.Realm, realm)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeRealmExists(w, named.Realm)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if created.ID != realm.ID {
		// ensureRealm converged onto an existing row rather than creating one,
		// which on this route means the name was taken. CreateRealm is
		// idempotent because startup calls it; the API is not.
		writeRealmExists(w, named.Realm)
		return
	}

	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+named.Realm)
	w.WriteHeader(http.StatusCreated)
}

// updateRealm serves PUT /admin/realms/{realm}.
//
// **It merges, and it renames.** A body of {} answers 204 and changes nothing;
// a body naming only `realm` renames the realm and keeps its id, so the path
// segment and the body do not have to agree and the body wins when they do not.
// That is the opposite of PUT on a role, which replaces, and neither a client
// nor a user can be renamed through its own PUT.
func (h *handler) updateRealm(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		// Keycloak's own NullPointerException, reproduced: a PUT with no body
		// at all is a 500 where the same body on POST is a 400.
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
			"For more on this error consult the server log.")
		return
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		// And a third spelling of "cannot parse the JSON" on one resource:
		// POST answers errorMessage "unable to read contents from stream".
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return
	}

	rep, err := h.realmRepresentationOf(r.Context(), rc.realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// **attributes is the one field a PUT replaces**, and not cleanly: a realm
	// created with {"a":"1","b":"2"} answered PUT {"attributes":{"c":"3"}} with
	// c and seven derived policy attributes, having dropped a, b and
	// realmReusableOtpCode. Nilling the map before the merge is what makes
	// encoding/json replace it instead of merging into it.
	if _, ok := fields["attributes"]; ok {
		rep.Attributes = nil
	}
	if err := applyRealmFields(&rep, fields); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return
	}
	if _, ok := fields["attributes"]; ok {
		restoreDerivedAttributes(&rep, rc.realm.Name)
	}

	was := rc.realm.Name
	renamed := rep.Realm != "" && rep.Realm != was
	if renamed {
		rc.realm.Name = rep.Realm
	}
	rc.realm.Enabled = rep.Enabled
	applyLifespans(rc.realm, &rep)
	rc.realm.Settings = marshalRealmSettings(&rep)

	if err := h.store.Realms().Update(r.Context(), rc.realm); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// A different wording from the one POST uses for the same
			// collision. Two ways to collide on one resource, two messages.
			httpx.WriteAdminError(w, http.StatusConflict, "Realm with same name exists")
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if renamed {
		if err := h.renameRealmClients(r.Context(), rc.realm, was); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	httpx.WriteNoContent(w, r)
}

// renameRealmClients is the half of a rename that is not the realm row.
//
// Measured on rn1 renamed to rn2: master's rn1-realm client became rn2-realm,
// its 21 roles and master's 43 admin composites were untouched, and the
// renamed realm's own account, account-console and security-admin-console
// clients had their baseUrl and redirectUris rewritten to the new name.
//
// **default-roles-rn1 kept its old name**, and so does Gloak's: the realm role
// is not renamed, its description is not touched, and the realm's defaultRole
// still names it. That is the one thing about a rename that looks like an
// oversight and is the contract.
func (h *handler) renameRealmClients(ctx context.Context, realm *model.Realm, was string) error {
	master, err := h.store.Realms().ByName(ctx, bootstrap.MasterRealmName)
	if err != nil {
		return err
	}
	container, err := h.store.Clients().ByClientID(ctx, master.ID, masterContainerFor(was))
	switch {
	case err == nil:
		container.ClientID = masterContainerFor(realm.Name)
		container.Name = realm.Name + " Realm"
		if err := h.store.Clients().Update(ctx, container); err != nil {
			return err
		}
	case errors.Is(err, store.ErrNotFound):
		// master itself cannot be renamed - the route refuses to delete it and
		// nothing creates a second - so there is no container to move.
	default:
		return err
	}

	for _, clientID := range []string{"account", "account-console", "security-admin-console"} {
		c, err := h.store.Clients().ByClientID(ctx, realm.ID, clientID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		c.BaseURL = strings.ReplaceAll(c.BaseURL, "/"+was+"/", "/"+realm.Name+"/")
		for i, uri := range c.RedirectURIs {
			c.RedirectURIs[i] = strings.ReplaceAll(uri, "/"+was+"/", "/"+realm.Name+"/")
		}
		if err := h.store.Clients().Update(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

// deleteRealm serves DELETE /admin/realms/{realm}.
//
// Deleting master is a **400**, not a 403 or a 409, and the message carries an
// apostrophe and no full stop.
func (h *handler) deleteRealm(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if rc.realm.Name == bootstrap.MasterRealmName {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Can't remove master realm")
		return
	}
	if err := bootstrap.DeleteRealm(r.Context(), h.store, rc.realm); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Defensive rather than reachable: the guard resolved this realm
			// before the handler ran, so only a delete racing another one
			// arrives here. It shares the helper so the two cannot drift.
			writeRealmNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.keys.Forget(rc.realm.ID)
	httpx.WriteNoContent(w, r)
}

// writeRealmStreamError is POST's answer to a body it cannot read: an absent
// one and a malformed one are the same 400, and it is a fourth spelling of
// "cannot parse the JSON" on this API - POST /users says invalid_request with
// "Cannot parse the JSON", the ten role-array endpoints say unknown_error with
// the same description, and PUT on this very resource says the first of those.
func writeRealmStreamError(w http.ResponseWriter) {
	httpx.WriteAdminError(w, http.StatusBadRequest, "unable to read contents from stream")
}

func writeRealmExists(w http.ResponseWriter, name string) {
	httpx.WriteAdminError(w, http.StatusConflict, "Realm "+name+" already exists")
}

// applyRealmFields merges a request body over a representation.
//
// A key that is **absent** and a key that is **null** both leave the field
// alone; a key carrying a value writes it, including an empty string. Measured:
// PUT {"displayName":null} left a previously set name in place and
// PUT {"displayName":""} produced "displayName":"" in the body. Go's decoder
// sets a pointer field to nil on an explicit null, so the nulls are dropped
// before the merge rather than after.
func applyRealmFields(rep *realmRepresentation, fields map[string]json.RawMessage) error {
	kept := make(map[string]json.RawMessage, len(fields))
	for k, v := range fields {
		if string(v) == "null" {
			continue
		}
		kept[k] = v
	}
	body, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, rep)
}

// restoreDerivedAttributes puts back the seven policy attributes a PUT that
// replaced the map loses. Measured: after PUT {"attributes":{"c":"3"}} the map
// held c and these seven, and realmReusableOtpCode - which the defaults carry -
// was gone. So this is not "the defaults again"; it is the seven, and the
// eighth stays lost.
func restoreDerivedAttributes(rep *realmRepresentation, realmName string) {
	defaults := defaultRealmAttributes(realmName)
	if rep.Attributes == nil {
		rep.Attributes = map[string]string{}
	}
	for _, key := range derivedRealmAttributes {
		if v, ok := defaults[key]; ok {
			rep.Attributes[key] = v
		}
	}
}

// realmRepresentationOf assembles the full body: the measured defaults for this
// realm's name, the settings blob over them, and then the five fields the realm
// row owns, so the row is the only observable truth for those and the blob's
// copies can never be read.
func (h *handler) realmRepresentationOf(ctx context.Context, realm *model.Realm) (realmRepresentation, error) {
	rep, err := decodeRealmSettings(realm)
	if err != nil {
		return rep, err
	}
	rep.ID = realm.ID
	rep.Realm = realm.Name
	rep.Enabled = realm.Enabled
	rep.AccessTokenLifespan = int(realm.AccessTokenLifespan.Seconds())
	rep.SSOSessionIdleTimeout = int(realm.RefreshTokenLifespan.Seconds())

	// defaultRole is derived rather than stored: its id and containerId are the
	// store's, so a copy in the blob would be a second truth able to go stale.
	role, err := h.store.Roles().ByName(ctx, realm.ID, "", model.DefaultRolesName(realm.Name))
	if err == nil {
		brief := roleRepresentationOf(role, realm.ID, true)
		rep.DefaultRole = &brief
	} else if !errors.Is(err, store.ErrNotFound) {
		return rep, err
	}
	return rep, nil
}

// decodeRealmSettings is the defaults for this realm's name with whatever has
// been written over them. A realm with no settings - one bootstrapped before
// the column existed - reads as the defaults, which is why nothing had to
// backfill the column.
func decodeRealmSettings(realm *model.Realm) (realmRepresentation, error) {
	rep := defaultRealmRepresentation(realm.Name)
	if len(realm.Settings) == 0 {
		return rep, nil
	}
	// **The two maps are nilled before the decode and the rest is not.**
	// encoding/json merges an object into a non-nil map and replaces a slice,
	// so leaving Attributes populated would let the defaults reappear inside a
	// map a PUT had deliberately replaced - which is exactly how
	// realmReusableOtpCode came back after a PUT that measured it gone.
	rep.Attributes = nil
	rep.SMTPServer = nil
	if err := json.Unmarshal(realm.Settings, &rep); err != nil {
		return rep, err
	}
	return rep, nil
}

// marshalRealmSettings writes the representation back for storage. A marshal
// failure is impossible for this struct - it holds no channels, functions or
// NaNs - so it is dropped rather than propagated, the same judgement
// internal/store/sqlite's encode makes.
func marshalRealmSettings(rep *realmRepresentation) []byte {
	b, err := json.Marshal(rep)
	if err != nil {
		return nil
	}
	return b
}

// applyLifespans copies the two representation fields the realm row owns back
// onto it. ssoSessionIdleTimeout is Gloak's refresh token lifespan: the two are
// the same 1800 seconds on both measured realms, and Keycloak has no separate
// refreshTokenLifespan in the representation at all.
func applyLifespans(realm *model.Realm, rep *realmRepresentation) {
	realm.AccessTokenLifespan = secondsToDuration(rep.AccessTokenLifespan)
	realm.RefreshTokenLifespan = secondsToDuration(rep.SSOSessionIdleTimeout)
}

func secondsToDuration(s int) time.Duration { return time.Duration(s) * time.Second }

// mayViewRealm reports whether a caller's names on the realm's container earn
// the full representation. realm-admin is not on this list and does not need to
// be: it is composite over the other 21 and internal/roles expands it.
func mayViewRealm(names map[string]bool) bool {
	return names["view-realm"] || names["manage-realm"]
}

// opensARealm reports whether a set of admin role names lets its holder see a
// realm at all.
//
// **impersonation is the one admin role of the 21 that does not**, measured
// against every one of them on a realm created for the sweep. There is no rule
// behind that which the name predicts, so it is written as the exclusion it is
// rather than as a list of the twenty that do.
func opensARealm(names map[string]bool) bool {
	for name := range names {
		if name != "impersonation" {
			return true
		}
	}
	return false
}

// namesOnContainerFor is the caller's admin role names on the container that
// decides what it may do to one realm. It is the listing's per-row question,
// where resolveCaller answered it once for the realm in the path.
func (h *handler) namesOnContainerFor(ctx context.Context, c *caller, realmName string) (map[string]bool, error) {
	container, err := h.containerFor(ctx, c.authRealm, realmName)
	if err != nil {
		return nil, err
	}
	// containerRoleNames rather than adminRoleNames: the two master-only realm
	// roles must not count here. A caller holding only create-realm is 403 on
	// this listing and 200 on the single read of every realm, measured, and
	// counting it would have shown it every realm.
	return containerRoleNames(container, c.effective), nil
}

// maySeeRealm is GET /admin/realms/{realm}'s admission, and it is **wider than
// every other route's**.
//
// A caller in master holding any admin role on any container - even the realm
// role create-realm, which owns no container at all - reads every realm at the
// reduced level, measured. Nothing reaches the other way: a caller inside
// another realm is 403 for every realm but its own, including for master.
//
// So this is the one place a master caller's rights cross a realm boundary, and
// it does not extend to the realm's users, clients or roles, which answer 403 to
// the same caller.
func (h *handler) maySeeRealm(ctx context.Context, c *caller, realmName string) (bool, error) {
	if c.authRealm.Name != bootstrap.MasterRealmName {
		if c.authRealm.Name != realmName {
			return false, nil
		}
		return opensARealm(c.adminGrants), nil
	}
	names, err := h.adminRolesAnywhere(ctx, c)
	if err != nil {
		return false, err
	}
	return opensARealm(names), nil
}

// adminRolesAnywhere is the caller's admin role names across **every** admin
// container in the realm it authenticated in, rather than the one container
// this request's guards use. Only maySeeRealm asks for it.
//
// A client whose row is gone is skipped rather than reported: F29 leaves a
// client's roles behind when the client is deleted, and an orphan cannot be an
// admin role of a living container. Every other error propagates, because "the
// container could not be read" and "the container is not there" are different
// facts and only the second means "confers nothing".
func (h *handler) adminRolesAnywhere(ctx context.Context, c *caller) (map[string]bool, error) {
	out := make(map[string]bool, len(c.effective))
	isContainer := make(map[string]bool, 2)
	for _, role := range c.effective {
		if role.ClientID == "" {
			if role.Name == "admin" || role.Name == "create-realm" {
				out[role.Name] = true
			}
			continue
		}
		if _, seen := isContainer[role.ClientID]; !seen {
			client, err := h.store.Clients().ByID(ctx, c.authRealm.ID, role.ClientID)
			switch {
			case err == nil:
				isContainer[role.ClientID] = isAdminContainerName(c.authRealm.Name, client.ClientID)
			case errors.Is(err, store.ErrNotFound):
				isContainer[role.ClientID] = false
			default:
				return nil, err
			}
		}
		if isContainer[role.ClientID] {
			out[role.Name] = true
		}
	}
	return out, nil
}

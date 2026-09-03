package admin

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// organizationMemberRepresentation is what the member routes serve.
//
// **A member is a user**, addressed by the user's own id: `POST .../members`
// carrying a user id answers 201 with a `Location` ending in that same id, the
// single read addresses the user by it, and the representation's `id` is the
// user's. No membership id is ever minted and none is ever served. That is why
// this embeds userRepresentation rather than declaring a shape of its own -
// encoding/json flattens an embedded struct in place, so the field order comes
// out as measured with `membershipType` last.
//
// Two keys `GET /users/{id}` carries are **absent** here: `access`, which is a
// statement about the caller, and `federatedIdentities`, which Gloak's
// userRepresentation does not have at all. So one user now serialises five ways
// on this API, after the three AGENTS.md records.
//
// MembershipType is a plain string and always `UNMANAGED`. `MANAGED` is what a
// user the organization itself provisioned carries - through a completed
// invitation or an identity provider link - and neither is reachable without a
// mail sender, so there is nothing for a stored value to vary over. See
// 0025_organization_member.sql.
type organizationMemberRepresentation struct {
	userRepresentation
	MembershipType string `json:"membershipType"`
}

// organizationMemberOf builds one member's representation.
//
// It reuses userRepresentationOf **including its attributes handling**, and
// that is a decision rather than an oversight. Keycloak's brief shape drops
// `attributes` for an attribute the realm's user profile declares and keeps it
// for one the profile does not know about: master's `is_temporary_admin`
// survives `briefRepresentation=true` - which is what admin/users/list-brief's
// golden holds - while a declared one does not, both measured with
// `unmanagedAttributePolicy` unset. Gloak has no user profile and no route that
// writes an undeclared attribute, so the only user it can serve with any is the
// bootstrapped administrator, whose attribute is of the kind Keycloak keeps.
func organizationMemberOf(u *model.User, brief bool) organizationMemberRepresentation {
	return organizationMemberRepresentation{
		userRepresentation: userRepresentationOf(u, brief),
		MembershipType:     organizationMembershipUnmanaged,
	}
}

// organizationMembershipUnmanaged is the only membershipType this project can
// produce. It is a constant rather than a literal so that the handler and the
// tests name one thing.
const organizationMembershipUnmanaged = "UNMANAGED"

// listOrganizationMembers serves GET /organizations/{org-id}/members.
//
// **It pages by default, and no other listing in this API does.** With no
// parameters at all it answered ten rows of twelve; `max=100` answered twelve.
// So `max` defaults to 10 and `first` to 0, where the role listings need
// `search` or both bounds, the group listing pages on either, and the user
// listing returns everything. A negative bound means no bound - `max=-1`
// answered all twelve - and `first=-1` behaves as 0 while the default `max`
// still applies.
//
// briefRepresentation defaults to **true** here and is ignored by the single
// read, which is the organization pair's rule one path segment up.
func (h *handler) listOrganizationMembers(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	members, ok := h.organizationMembers(w, r, o)
	if !ok {
		return
	}
	q := r.URL.Query()
	members = filterOrganizationMembers(members, q)
	members = pageOrganizationMembers(members, q)

	full := q.Get("briefRepresentation") == "false"
	out := make([]organizationMemberRepresentation, 0, len(members))
	for _, u := range members {
		out = append(out, organizationMemberOf(u, !full))
	}
	writeAdminJSON(w, out)
}

// countOrganizationMembers serves GET /organizations/{org-id}/members/count.
//
// **It reads none of the listing's parameters.** `?search=lm-03` and
// `?membershipType=MANAGED` both answered 12 on a twelve-member organization
// whose listing answered one row and none. The organization count one path
// segment up honours its own `search`, so the two counts on this resource
// disagree about whether a count is filtered, and passing the query through
// "for consistency" is the change that breaks this one.
//
// The body is a bare JSON number, like the organization count and
// GET /users/count and unlike GET /groups/count's object.
func (h *handler) countOrganizationMembers(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	members, ok := h.organizationMembers(w, r, o)
	if !ok {
		return
	}
	writeAdminJSON(w, len(members))
}

// readOrganizationMember serves GET /organizations/{org-id}/members/{member-id}.
//
// It writes the full shape unconditionally: `?briefRepresentation=true`
// answered a body byte-identical to the one with no parameter, which is the
// organization single read's rule again. And the body it writes is
// byte-identical to a `briefRepresentation=false` listing entry - checked as
// bytes rather than by eye - so the family has exactly two shapes.
func (h *handler) readOrganizationMember(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	u, ok := h.organizationMemberFromPath(w, r, rc, o)
	if !ok {
		return
	}
	writeAdminJSON(w, organizationMemberOf(u, false))
}

// addOrganizationMember serves POST /organizations/{org-id}/members.
//
// **The body is the user id as raw bytes and it is not JSON.** Measured over
// eight bodies on 2026-09-02 - see organizationMemberID for the rule and the
// probes. A handler that decodes the body with encoding/json is right on the
// quoted form and wrong on four of the others.
//
// The 201 carries a `Location` ending in the id the **caller sent**, not a
// server-minted one, so it is the fifth create in this API whose tail the
// caller chose. It carries no Content-Type and an empty body.
//
// A user id that resolves to nothing is the generic
// `404 {"error":"HTTP 404 Not Found"}` - an ordinary missing row producing that
// body - and so is a user of another realm. A user who is already a member is
// `409 {"errorMessage":"User is already a member of the organization."}`, with
// a full stop, where invite-user's sentence for the same condition has none and
// a different word order.
//
// **An absent Content-Type is accepted and `text/plain`,
// `application/x-www-form-urlencoded` and `application/xml` are 415**, which is
// requireJSONBody's rule exactly - measured here by building the request at
// socket level, because the obvious probe cannot see it: Python's urllib adds
// `application/x-www-form-urlencoded` to any POST carrying data that does not
// already name one, so a probe that sends "no Content-Type" measures the 415 of
// a header it set itself. That is how this cut first got the rule backwards,
// and the recorder is what caught it - it builds the request by hand and got
// the 409 where the probe had got a 415. A **present but empty** Content-Type
// is a third answer, `500 unknown_error`, and is not reproduced.
func (h *handler) addOrganizationMember(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	if !requireJSONBody(w, r) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	userID := organizationMemberID(body)
	u, err := h.store.Users().ByID(r.Context(), rc.realm.ID, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeOrganizationMemberNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	switch err := h.store.Organizations().AddMember(r.Context(), o.ID, u.ID); {
	case errors.Is(err, store.ErrConflict):
		httpx.WriteAdminError(w, http.StatusConflict,
			"User is already a member of the organization.")
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+
		"/organizations/"+o.ID+"/members/"+u.ID)
	w.WriteHeader(http.StatusCreated)
}

// removeOrganizationMember serves DELETE /organizations/{org-id}/members/{member-id}.
//
// It removes the membership and **not the user**: the user still reads 200
// afterwards. It is not idempotent - the second delete is the generic 404, and
// so is a delete naming a user who exists and is not a member, so the two cases
// are indistinguishable on the wire.
func (h *handler) removeOrganizationMember(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	switch err := h.store.Organizations().RemoveMember(r.Context(), o.ID, r.PathValue("memberID")); {
	case errors.Is(err, store.ErrNotFound):
		writeOrganizationMemberNotFound(w)
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// listOrganizationMemberGroups serves
// GET /organizations/{org-id}/members/{member-id}/groups.
//
// It answers the member's memberships of the *organization's* groups, at any
// depth, in the five-key listing shape - measured 2026-09-03 on a member of one
// group and its child, which came back as two flat rows.
//
// **This was an unconditional `[]` until this cut**, with a comment saying the
// groups it would answer were F120's and could not exist. They can now, and the
// realm's own `GET /users/{id}/groups` is **not** where the rows come from: that
// route filters organization groups out, while `GET /users/{id}/groups/count`
// beside it counts them.
//
// It still resolves the member first: a user who is not a member of this
// organization is the generic 404, measured.
func (h *handler) listOrganizationMemberGroups(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	u, ok := h.organizationMemberFromPath(w, r, rc, o)
	if !ok {
		return
	}
	all, err := h.store.Groups().ListOrganizationAll(r.Context(), rc.realm.ID, o.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	var held []*model.Group
	for _, g := range all {
		members, err := h.store.Groups().Members(r.Context(), rc.realm.ID, g.ID)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		for _, m := range members {
			if m.ID == u.ID {
				held = append(held, g)
				break
			}
		}
	}
	h.writeOrganizationGroups(w, r, rc, held, organizationGroupBrief)
}

// listOrganizationMemberOrganizations serves
// GET /organizations/{org-id}/members/{member-id}/organizations.
//
// It serves the **brief organization shape** and honours briefRepresentation,
// which defaults to true; `false` adds `attributes`. Its body for a member is
// byte-identical to the top-level route's below, and the two disagree in two
// places: this one is a 404 for a user who is not a member of the path's
// organization where that one answers 200 and `[]`, and their guards differ.
func (h *handler) listOrganizationMemberOrganizations(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	u, ok := h.organizationMemberFromPath(w, r, rc, o)
	if !ok {
		return
	}
	h.writeMemberOrganizations(w, r, rc, u.ID)
}

// writeMemberOrganizations is the body of the route above.
//
// It is a function of its own because the family has a **second** route serving
// byte-identical bytes - `GET /organizations/members/{member-id}/organizations`,
// with no organization in its path - which this project does not serve. That
// route's own behaviour is measured (it does not check membership: a user of
// the realm who belongs to no organization answers 200 and `[]`, where the
// route above answers 404 for the same user) and the reason it is unserved is a
// `net/http` pattern conflict spelled out in router.go beside where it would be
// registered.
func (h *handler) writeMemberOrganizations(w http.ResponseWriter, r *http.Request, rc *reqContext, userID string) {
	orgs, err := h.store.Organizations().MemberOf(r.Context(), rc.realm.ID, userID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	full := r.URL.Query().Get("briefRepresentation") == "false"
	out := make([]organizationRepresentation, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, organizationRepresentationOf(o, full))
	}
	writeAdminJSON(w, out)
}

// organizationMembers loads an organization's members or writes the 500.
func (h *handler) organizationMembers(w http.ResponseWriter, r *http.Request, o *model.Organization) ([]*model.User, bool) {
	members, err := h.store.Organizations().Members(r.Context(), o.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return members, true
}

// organizationMemberFromPath resolves the `{member-id}` segment of the four
// routes that name one.
//
// **A user who exists and is not a member and a user id that resolves to
// nothing get the same answer**, the generic
// `404 {"error":"HTTP 404 Not Found"}`, so this returns one failure rather than
// two. Measured on both, on all four routes.
func (h *handler) organizationMemberFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) (*model.User, bool) {
	u, err := h.store.Users().ByID(r.Context(), rc.realm.ID, r.PathValue("memberID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeOrganizationMemberNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	member, err := h.store.Organizations().IsMember(r.Context(), o.ID, u.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	if !member {
		writeOrganizationMemberNotFound(w)
		return nil, false
	}
	return u, true
}

// writeOrganizationMemberNotFound is the 404 four routes in this family answer.
//
// **It is the generic `{"error":"HTTP 404 Not Found"}` and not one of the
// twenty-five spellings of not-found**, which makes the member routes a sixth
// producer of that body after an unmatched path, a wrong verb, a switched-off
// resource, an unparseable integer bound and the authorization resource family.
// The same bytes answer a user id that resolves to nothing, a user of another
// realm, and a user of this realm who is not a member - so nothing on the wire
// tells the three apart.
func writeOrganizationMemberNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
}

// organizationMemberID reads the user id out of a POST .../members body.
//
// **The body is not JSON**, and the rule is: trim whitespace, then strip at
// most one `"` from each end. Measured over eight bodies on 2026-09-02, all
// against a user that exists:
//
//	"2a04b3cf-…"           201   a JSON string
//	2a04b3cf-…             201   no quotes at all - not valid JSON
//	"2a04b3cf-…            201   one leading quote
//	2a04b3cf-…"            201   one trailing quote
//	  2a04b3cf-…           201   surrounding spaces, and tabs likewise
//	2a04b3c"f-…            404   a quote in the middle
//	""2a04b3cf-…""         404   two quotes at each end
//	'2a04b3cf-…'           404   single quotes
//	["2a04b3cf-…"]         404   a JSON array of one
//	{"id":"2a04b3cf-…"}    404   a UserRepresentation
//
// `""x""` failing is what says "at most one", and the mid-string quote failing
// is what says "at the ends". A json.Unmarshal into a string is right on the
// first row and wrong on the four below it that succeed.
func organizationMemberID(body []byte) string {
	s := strings.TrimSpace(string(body))
	s = strings.TrimPrefix(s, `"`)
	s = strings.TrimSuffix(s, `"`)
	return s
}

// filterOrganizationMembers applies search, exact and membershipType.
//
// **membershipType is compared against the one value this project can hold.**
// An unknown value is a 500 on Keycloak - Jackson refusing to bind the enum -
// and that is not reproduced: a filter answering an empty list is the honest
// answer for a value Gloak has no rows for, and inventing the 500 would mean
// carrying Keycloak's enum by name.
func filterOrganizationMembers(in []*model.User, q url.Values) []*model.User {
	out := in
	if search := q.Get("search"); search != "" {
		exact := q.Get("exact") == "true"
		var kept []*model.User
		for _, u := range out {
			if organizationMemberMatches(u, search, exact) {
				kept = append(kept, u)
			}
		}
		out = kept
	}
	if want := q.Get("membershipType"); want != "" {
		if !strings.EqualFold(want, organizationMembershipUnmanaged) {
			return nil
		}
	}
	return out
}

// organizationMemberMatches is how search compares on this family, and it is
// **not** how the user listing's does.
//
// The two were measured side by side on one container against one realm, with a
// member named `gloak-probe-lm-03`:
//
//	GET /organizations/{org}/members?search=lm-03   matched it
//	GET /users?search=lm-03                          answered []
//
// So the user listing's `search` is a prefix - `term` becomes `term%` - and
// this one is an **infix**, `%term%`. Neither end is anchored. `*` is the
// wildcard and stands for any run; `%` and `_` are literals - `%lph%` and
// `_lpha` both found nothing where `*lph*` and `lph` found the row - and
// `"quotes"` do **not** mean equality here, where they do on the user listing:
// `search="gloak-probe-lm-03"` answered `[]`.
//
// The four fields are username, firstName, lastName and email; the id is not
// among them - the member's own full id and its first eight characters both
// found nothing.
//
// exact compares the whole value against each of the same four fields, and
// `exact=bogus` behaves as false.
func organizationMemberMatches(u *model.User, search string, exact bool) bool {
	for _, field := range []string{u.Username, u.FirstName, u.LastName, u.Email} {
		if exact {
			if strings.EqualFold(field, search) {
				return true
			}
			continue
		}
		if containsWildcard(field, search) {
			return true
		}
	}
	return false
}

// containsWildcard reports whether value contains term, case-insensitively,
// with `*` standing for any run of characters and neither end anchored.
//
// It is written out rather than expressed as matchesSearch with a `*` glued to
// the front, although that would give the same answers today. The two rules
// belong to two families that have already been measured disagreeing, and a
// call from one into the other is what would carry a later correction of the
// user listing's rule silently into this one.
func containsWildcard(value, term string) bool {
	value = strings.ToLower(value)
	term = strings.ToLower(term)
	for i, run := range strings.Split(term, "*") {
		if run == "" {
			continue
		}
		idx := strings.Index(value, run)
		if idx < 0 {
			return false
		}
		_ = i
		value = value[idx+len(run):]
	}
	return true
}

// pageOrganizationMembers applies first and max, **with max defaulting to 10**.
//
// That default is the finding: with no parameters at all the listing answered
// ten rows of twelve. It is not pageGroups with an argument, because the two
// rules differ in more than the number - a negative `max` here means no bound
// where pageGroups ignores it, and an absent `max` here is 10 where pageGroups
// leaves the list alone.
//
// A malformed bound - `?max=abc` - is a `404 {"error":"HTTP 404 Not Found"}` on
// Keycloak and is **not** reproduced: it is F134's, it is per family rather
// than per API, and the organization listing beside this one already ignores
// it. An unparseable bound falls back to the default here.
func pageOrganizationMembers[T any](in []T, q url.Values) []T {
	const defaultMax = 10
	out := in
	if v, err := strconv.Atoi(q.Get("first")); err == nil && v > 0 {
		if v >= len(out) {
			return out[:0]
		}
		out = out[v:]
	}
	max := defaultMax
	if v, err := strconv.Atoi(q.Get("max")); err == nil {
		max = v
	}
	if max >= 0 && max < len(out) {
		out = out[:max]
	}
	return out
}

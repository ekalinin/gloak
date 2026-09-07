// Package account serves Keycloak's account REST API, the surface a user
// reaches under /realms/{realm}/account.
//
// It is a third API and not a variation on either of the other two, and three
// measured facts say so.
//
// **The path is two APIs and the Accept header picks.** One path answers the
// account console's single-page application to a browser and the REST resource
// to a caller that asked for JSON, so the enumeration of this surface cannot
// use the discriminator the SAML sweep used: without an Accept header every
// path under /realms/{realm}/account - including ones no route serves -
// answers 200 with the console's HTML, and the two 404 bodies never appear.
// Gloak serves the REST branch for every Accept, because the console is a
// theme resource and the themes chapter is not enumerated; the divergence is
// a case of its own, account/console/accept-html.
//
// **The gate is two stages and they answer with different statuses.** A
// caller whose token grants no role on the realm's `account` client is
// **401**, not 403 - measured on two tokens whose serialised `aud` claim is
// equally absent, one accepted and one refused, so the check is on the
// token's granted roles rather than on the claim. A caller past that stage
// holding the wrong account role is 403. Reading `aud` out of the token is
// the obvious implementation and it is wrong on both of those tokens at once.
//
// **The role sets are per route and no two of the three reads agree.**
// supportedLocales takes none at all, groups takes view-groups or
// manage-account, and linked-accounts takes view-profile or manage-account -
// and manage-account-links, whose name matches the route, is refused. One
// guard shared between the two served reads is wrong on one of them whichever
// way it is written.
//
// See docs/superpowers/handover/account-api.md for the enumeration and every
// measurement behind the values here.
package account

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/token"
)

// accountClientID is the clientId of the client every realm bootstraps to
// hold a user's own permissions over itself. It is the client the audience
// gate below asks about and the container the route role sets are read from.
const accountClientID = "account"

// The account client's roles this package's routes ask for. There are eight
// on a default install; these are the three the two served reads and the
// audience gate need. The other five - manage-account-links, manage-consent,
// view-applications, view-consent and delete-account - open routes this
// package does not serve, and manage-account-links is measured **not** to
// open the linked-accounts read that carries its name.
const (
	roleViewProfile   = "view-profile"
	roleManageAccount = "manage-account"
	roleViewGroups    = "view-groups"
)

type handler struct {
	store      store.Store
	keys       *keys.Manager
	issuerBase string
}

// Register adds the account API's routes to an existing mux, alongside the
// protocol and admin APIs, for oidc.Register's reason: the fallback shapes are
// decided by whether *any* route on the one mux matched, and a second mux
// would answer its own 404 for a path the first one owns.
func Register(mux *http.ServeMux, s store.Store, k *keys.Manager, issuerBase string) {
	h := &handler{store: s, keys: k, issuerBase: issuerBase}
	// The two reads that are pure functions of state Gloak already holds. The
	// rest of the surface is enumerated in internal/conformance/catalog_account.go
	// and deliberately not served; the handover says why for each.
	//
	// GET /realms/{realm}/account/supportedLocales is measured and **not**
	// here: it serves the realm's stored supportedLocales in stored order, and
	// Gloak stores none - realmReducedRepresentation sends a constant [] - so
	// a handler here could only ever return that constant and would pass a
	// golden recorded against master while being wrong on every realm that
	// has locales. That is the corpus-with-no-discriminating-case shape, and
	// the case is Recorded rather than Implemented for it.
	mux.HandleFunc("GET /realms/{realm}/account/groups", h.groups)
	mux.HandleFunc("GET /realms/{realm}/account/linked-accounts", h.linkedAccounts)
}

// subject is an authenticated account-API caller: the user behind the bearer
// token and the role names it holds **on the account client of the realm in
// the path**.
//
// The names are narrowed to that one container for internal/admin's reason,
// one API across: a role named view-profile on some other client is not this
// role, and asking about the name alone would let any client's owner mint one.
type subject struct {
	user  *model.User
	realm *model.Realm
	// grants holds the account client's role names this user effectively
	// holds, composites expanded.
	grants map[string]bool
}

// has reports whether the subject holds one account role by name.
func (s *subject) has(role string) bool { return s.grants[role] }

// hasAny reports whether the subject holds at least one of the roles a route
// accepts. Every served route takes two, and they are two different pairs.
func (s *subject) hasAny(names ...string) bool {
	for _, n := range names {
		if s.grants[n] {
			return true
		}
	}
	return false
}

// resolve runs the account API's gate in the measured order and returns the
// subject, or nil when it has already written the refusal.
//
//	realm            unknown -> 404 {"error":"Realm does not exist"}
//	bearer token     missing, malformed, unverifiable, or naming a dead
//	                 session -> 401 {"error":"HTTP 401 Unauthorized"}
//	account audience the user holds no role on the realm's account client
//	                 -> 401, the same bytes
//
// **The realm is resolved first, before the token and before the Accept
// header.** Measured with no Authorization header at all and with none of the
// three Accept spellings: /realms/nosuchrealm/account and
// /realms/nosuchrealm/account/groups both answer `Realm does not exist`, so
// the realm cannot be resolved after the caller.
//
// **The audience refusal is a 401 and the role refusal is a 403**, which is
// the split that makes this two stages rather than one. Collapsing them into
// a single 403 is right on every caller who holds some account role and wrong
// on every caller who holds none.
func (h *handler) resolve(w http.ResponseWriter, r *http.Request) *subject {
	realm, err := h.store.Realms().ByName(r.Context(), r.PathValue("realm"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusNotFound, "Realm does not exist")
			return nil
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}

	user := h.authenticate(w, r, realm)
	if user == nil {
		return nil
	}

	effective, err := roles.Effective(r.Context(), h.store.Roles(), user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}
	grants, err := h.accountGrants(r.Context(), realm, effective)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}
	// The audience stage. Measured on four token/user pairs: admin-cli, which
	// is a lightweight client whose access token carries **no aud claim at
	// all**, is accepted for a user holding account roles and refused 401 for
	// one holding none; and a client with fullScopeAllowed off is refused 401
	// for a user holding all of them. So the gate is the granted role set and
	// not the claim, and the two refused tokens are the pair that says so.
	if len(grants) == 0 {
		writeUnauthorized(w)
		return nil
	}
	return &subject{user: user, realm: realm, grants: grants}
}

// authenticate turns the bearer token into the user behind it, or writes the
// measured 401 and returns nil.
//
// **The token must have been issued by the realm in the path.** The account
// API is a user-facing API for one realm's own users; unlike internal/admin's,
// which accepts a master token for another realm, nothing here reaches across
// a realm boundary. That is not a guess about Keycloak - it is the narrower of
// the two behaviours, and the cross-realm cell is unmeasured and named in the
// handover.
//
// Every failure is the same 401, byte for byte with a missing header, which is
// measured: no header, `Bearer garbage`, a syntactically valid token that does
// not verify, and `Basic` credentials all answer the identical 33 bytes with
// all five security headers and **no WWW-Authenticate**.
func (h *handler) authenticate(w http.ResponseWriter, r *http.Request, realm *model.Realm) *model.User {
	raw := bearerToken(r)
	if raw == "" {
		writeUnauthorized(w)
		return nil
	}
	k, err := h.keys.ForRealm(r.Context(), realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}
	parsed, err := token.ParseAccess(k, h.issuerBase+"/realms/"+realm.Name, raw, time.Now())
	if err != nil {
		writeUnauthorized(w)
		return nil
	}
	session, err := h.store.Sessions().UserSessionByID(r.Context(), realm.ID, parsed.SessionID)
	if err != nil {
		writeUnauthorized(w)
		return nil
	}
	user, err := h.store.Users().ByID(r.Context(), realm.ID, session.UserID)
	if err != nil || !user.Enabled {
		writeUnauthorized(w)
		return nil
	}
	return user
}

// accountGrants reduces an expanded role set to the names owned by the realm's
// `account` client.
//
// **The container decides, never the name**, which is internal/admin's F32
// lesson applied to a second API before it can be learned here: a caller who
// can create a client can mint a role called manage-account on it, and a name
// test would then hand that caller the whole account API.
//
// A realm with no account client is a realm where every caller is refused, and
// that falls out of returning an empty set rather than needing a branch: the
// bootstrap creates the client, so the state is unreachable, and a lookup
// failure that answered 500 would turn a missing bootstrap row into a server
// error instead of a refusal.
func (h *handler) accountGrants(ctx context.Context, realm *model.Realm, effective []*model.Role) (map[string]bool, error) {
	container, err := h.store.Clients().ByClientID(ctx, realm.ID, accountClientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	grants := make(map[string]bool)
	for _, role := range effective {
		if role.ClientID == container.ID {
			grants[role.Name] = true
		}
	}
	return grants, nil
}

// bearerToken reads the access token out of the Authorization header.
//
// **The scheme folds case.** `bearer <t>`, `BEARER <t>` and `BeArEr <t>` were
// all measured answering 200 on /realms/master/account/groups with a token that
// answers 200 as `Bearer <t>`. The admin API folds it too - measured on
// /admin/realms/master with an administrator's token - which internal/admin's
// own bearerToken does not do; that is its divergence and not this one's, and
// the handover files it.
//
// **Exactly one space separates the scheme from the token, and whitespace
// around the whole value is ignored.** Sixteen spellings were measured on one
// path with one token, and the two halves of that sentence are separate
// findings:
//
//	Bearer <t>                200      the ordinary spelling
//	bearer <t> BEARER <t>     200      the scheme folds case
//	Bearer  <t>               401      two spaces
//	Bearer   <t>              401      three spaces
//	Bearer\t<t>               401      a tab is not the separator
//	Bearer <t><space>         200      trailing whitespace is ignored
//	Bearer <t><space><space>  200
//	Bearer <t>\t              200
//	<space>Bearer <t>         200      leading whitespace is ignored
//	<space><space>Bearer <t>  200
//	Bearer<t>                 401      no separator at all
//	Bearer <t> extra          401      a third token is refused
//	Bearer, <t>               401      the scheme is compared whole
//	Bearer / "Bearer "        401      no token
//	Basic <creds>             401
//	Negotiate <t> DPoP <t>    401      a valid token under another scheme
//
// Every row above was re-measured on 2026-09-07 against a fresh 26.7.1 and all
// sixteen reproduce.
//
// **A version that trimmed the remainder passed all of this except the three
// refusals in the middle**, and that is how it was found: `strings.TrimSpace`
// over the part after the first space turns `Bearer  <t>` into a 200 where
// Keycloak answers 401. Trimming the whole value first and then refusing a
// remainder that still holds a space is what fits all sixteen rows.
// account/gate/double-space-scheme is the case that holds that end of it, and
// the space is **inside** the value, so no HTTP stack removes it.
//
// **The other end has no case and cannot have one.** A leading or trailing
// space is optional whitespace around the field value, and a conformant
// receiver strips it before any handler runs: measured, a Go client sending
// `" Bearer tok"` over a real socket is read by the server as `"Bearer tok"`,
// while the same value handed to a handler in-process arrives with the space
// intact. So a conformance case for it would compare 200 against 200 for two
// different reasons - the recorder's Keycloak never sees the space and the
// verifier's Gloak sees it and trims it - which is a case measuring the harness
// rather than the server. The outer TrimSpace here is therefore defensive
// rather than measured, and it is kept because this function is also called
// from tests that construct a request directly. See F191.
func bearerToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, rest, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.Contains(rest, " ") {
		return ""
	}
	return rest
}

// writeUnauthorized emits the measured 401. It is the fallback family's shape
// - `{"error":"HTTP 401 Unauthorized"}` - which that family was not previously
// known to have: the four bodies recorded for it are 404 Not Found, 405 Method
// Not Allowed, 406 Not Acceptable and the unmatched-path sentence.
func writeUnauthorized(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusUnauthorized, "HTTP 401 Unauthorized")
}

// writeForbidden emits the measured 403 for a caller past the audience stage
// holding none of the route's roles.
func writeForbidden(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusForbidden, "HTTP 403 Forbidden")
}

// writeAccountJSON writes a 200 the way every measured account API success
// writes one: `application/json;charset=UTF-8` and `Cache-Control: no-cache`.
//
// **The Cache-Control is not universal on this API and the exception is
// deliberate.** Six of the eight measured 200s carry `no-cache` - the profile
// read, credentials, sessions, sessions/devices, applications and groups - and
// two carry none at all: linked-accounts and supportedLocales. So this writer
// serves the groups read and linkedAccounts sets its own headers; a single
// writer used by both would be wrong on one of them, which is AGENTS.md's
// "Cache-Control is pinned per endpoint" met on a third API.
func writeAccountJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, body)
}

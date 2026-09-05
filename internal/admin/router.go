package admin

import (
	"errors"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

type handler struct {
	store      store.Store
	keys       *keys.Manager
	issuerBase string
}

// Register adds the Admin REST API to an existing mux.
//
// It registers onto a caller's mux rather than building its own, and does no
// wrapping. The security headers and the two measured fallback 404 shapes
// belong to the whole server, not to this API: with a mux of its own, an
// unmatched admin path would produce a third 404 shape, and only two are
// measured. internal/oidc.WithKeycloakFallbacks wraps the composed result
// once.
func Register(mux *http.ServeMux, s store.Store, k *keys.Manager, issuerBase string) {
	h := &handler{store: s, keys: k, issuerBase: issuerBase}
	h.register(mux)
}

// register declares every route. Routes are added through h.guard so that a
// route with no required role cannot be written by accident: guard takes the
// role as a parameter, so omitting it does not compile.
func (h *handler) register(mux *http.ServeMux) {
	// The realm as a resource. The two collection routes carry no {realm}
	// segment, so neither resolveRealm nor any of the twelve combinators below
	// can serve them - guardRealms authenticates and hands the caller over.
	//
	// POST takes the realm role create-realm and nothing else: manage-realm and
	// realm-admin are both 403 on it, measured, and a create-realm holder is
	// 403 on the listing beside it. The collection's two verbs disagree about
	// who may use them in both directions.
	mux.HandleFunc("GET /admin/realms", h.guardRealms(h.listRealms))
	mux.HandleFunc("POST /admin/realms", h.guardRealmsWithRole("create-realm", h.createRealm))

	// The three that name a realm resolve it **before** judging the caller, so
	// an unknown realm is 404 to a caller holding nothing - guardAny's order,
	// which is guardGroup's and not guardUserSubject's.
	//
	// The read has its own guard because its admission is wider than any other
	// route's: see maySeeRealm. The two writes take manage-realm alone, on the
	// container the caller's rights come from, measured across all 21 roles.
	mux.HandleFunc("GET /admin/realms/{realm}", h.guardRealmRead(h.readRealm))
	mux.HandleFunc("PUT /admin/realms/{realm}", h.guardAny(realmWriteRoles, h.updateRealm))
	mux.HandleFunc("DELETE /admin/realms/{realm}", h.guardAny(realmWriteRoles, h.deleteRealm))

	// The realm half of the session family - four operations the description
	// tags `Realms Admin`, taking **three different guards**. Measured one role
	// at a time; nothing in the tag predicts any of them.
	//
	// client-session-stats is the realm read pair, push-revocation is
	// manage-realm alone, and logout-all and DELETE .../sessions/{session} are
	// **manage-users** alone - the users family's write role, on routes that
	// name no user. A manage-users caller gets 404 rather than 403 on the
	// delete, which is what says the role is checked before the session is
	// resolved.
	//
	// This is the third time the description's tag has failed to predict a
	// guard and the first time one tag has answered three ways at once.
	mux.HandleFunc("GET /admin/realms/{realm}/client-session-stats",
		h.guardAny(realmConfigReadRoles, h.clientSessionStats))
	mux.HandleFunc("POST /admin/realms/{realm}/push-revocation",
		h.guardAny(realmWriteRoles, h.pushRealmRevocation))
	mux.HandleFunc("POST /admin/realms/{realm}/logout-all",
		h.guardAny(userWriteRoles, h.logoutAll))
	mux.HandleFunc("DELETE /admin/realms/{realm}/sessions/{sessionID}",
		h.guardAny(userWriteRoles, h.deleteSession))

	// The whole of the description's Key tag. view-realm or manage-realm,
	// measured across all 22 realm-management roles and a caller holding none -
	// the same pair the realm's own configuration reads take, and measured on
	// this route rather than carried over from them.
	mux.HandleFunc("GET /admin/realms/{realm}/keys", h.guardAny(realmConfigReadRoles, h.readKeys))

	// The realm's default groups, and the read of a group by its path. The
	// description files all four under Realms Admin and they are **not** all
	// authorised alike: the three default-groups operations take the realm's
	// roles and group-by-path takes the users family's. Measured on each.
	//
	// **The two writes resolve the caller before the group, which no other
	// route naming a group does.** An unknown group id answers 403 to a
	// view-realm caller and to a caller holding nothing, where every Groups
	// route answers 404 to both. So these take guardAny and resolve the group
	// in the handler, and guardGroup would be wrong here - see
	// defaultGroupFromPath.
	mux.HandleFunc("GET /admin/realms/{realm}/default-groups",
		h.guardAny(realmConfigReadRoles, h.listDefaultGroups))
	mux.HandleFunc("PUT /admin/realms/{realm}/default-groups/{groupID}",
		h.guardAny(realmWriteRoles, h.addDefaultGroup))
	mux.HandleFunc("DELETE /admin/realms/{realm}/default-groups/{groupID}",
		h.guardAny(realmWriteRoles, h.removeDefaultGroup))

	// group-by-path is the Groups family's ordering and the Groups family's
	// roles, on a route the description tags Realms Admin: an unknown path
	// answers 404 to every caller including one holding nothing, and
	// query-groups - which opens the group listing - is 403 here.
	mux.HandleFunc("GET /admin/realms/{realm}/group-by-path/{path...}",
		h.guardGroupPath(groupReadRoles, h.readGroupByPath))

	// Client policies and client profiles. They are the same state the realm
	// representation's clientPolicies and clientProfiles keys carry, measured in
	// both directions, so the reads take the realm's read pair and the writes
	// take manage-realm - the guard PUT /admin/realms/{realm} takes, because it
	// is the same write.
	mux.HandleFunc("GET /admin/realms/{realm}/client-policies/policies",
		h.guardAny(realmConfigReadRoles, h.readClientPolicies))
	mux.HandleFunc("PUT /admin/realms/{realm}/client-policies/policies",
		h.guardAny(realmWriteRoles, h.updateClientPolicies))
	mux.HandleFunc("GET /admin/realms/{realm}/client-policies/profiles",
		h.guardAny(realmConfigReadRoles, h.readClientProfiles))
	mux.HandleFunc("PUT /admin/realms/{realm}/client-policies/profiles",
		h.guardAny(realmWriteRoles, h.updateClientProfiles))

	// Localization, seven operations. Measured 2026-09-03; see
	// docs/superpowers/plans/2026-09-03-realms-admin-remainder.md.
	//
	// **The three reads do not share one admission and the difference is one
	// path segment.** `GET .../localization/{locale}` takes
	// GET /admin/realms/{realm}'s own guard - a create-realm holder reads it,
	// and a master caller holding any master-realm admin role reads **another
	// realm's** texts in full - while the collection listing and the single-key
	// read beside it refuse both and take the realm container's roles instead.
	// Swept one role at a time over all 21 of the realm's container, the two
	// master-only realm roles and a caller holding none, on each of the three.
	// So this is the second read in this API measured reaching sideways across
	// a realm boundary, and its two siblings are not.
	//
	// The four writes take manage-realm alone, which the same sweep says.
	mux.HandleFunc("GET /admin/realms/{realm}/localization",
		h.guardRealmContainerAny(h.listLocales))
	mux.HandleFunc("GET /admin/realms/{realm}/localization/{locale}",
		h.guardRealmRead(h.readLocalizationTexts))
	mux.HandleFunc("POST /admin/realms/{realm}/localization/{locale}",
		h.guardAny(realmWriteRoles, h.importLocalizationTexts))
	mux.HandleFunc("DELETE /admin/realms/{realm}/localization/{locale}",
		h.guardAny(realmWriteRoles, h.deleteLocale))
	mux.HandleFunc("GET /admin/realms/{realm}/localization/{locale}/{key}",
		h.guardRealmContainerAny(h.readLocalizationText))
	mux.HandleFunc("PUT /admin/realms/{realm}/localization/{locale}/{key}",
		h.guardAny(realmWriteRoles, h.setLocalizationText))
	mux.HandleFunc("DELETE /admin/realms/{realm}/localization/{locale}/{key}",
		h.guardAny(realmWriteRoles, h.deleteLocalizationText))

	// The client description converter, and **it is not a Realms Admin guard**
	// although the description tags it one: manage-clients alone opens it,
	// measured across the same 22 callers, and manage-realm is 403. That is the
	// client-scope family's direction - the fourth time this tag has failed to
	// predict a guard - and the caller is judged **before** the body, so a
	// caller holding nothing gets 403 for a body that would have been a 400.
	mux.HandleFunc("POST /admin/realms/{realm}/client-description-converter",
		h.guard("manage-clients", h.convertClientDescription))

	// Client types, whose entire contract on a default 26.7.1 is a 501.
	// CLIENT_TYPES is a disabled preview feature, the same situation as
	// GET .../client-secret/rotated's permanent 404. See guardRealmFeature for
	// why this is not a guardAny with an empty role list.
	mux.HandleFunc("GET /admin/realms/{realm}/client-types", h.guardRealmFeature(writeFeatureNotEnabled))
	mux.HandleFunc("PUT /admin/realms/{realm}/client-types", h.guardRealmFeature(writeFeatureNotEnabled))

	// Organizations: the six operations that treat one as a resource.
	//
	// **Every one of them sits behind the realm's own organizationsEnabled
	// flag, and the check is after the caller's roles rather than before
	// them** - which is where this family differs from client-types above.
	// See guardOrganizations.
	//
	// The listing and the count take query-organizations as well as the read
	// pair, exactly the way the group listing takes query-groups and the
	// single group read does not.
	mux.HandleFunc("GET /admin/realms/{realm}/organizations",
		h.guardOrganizations(organizationsListReadRoles, h.listOrganizations))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/count",
		h.guardOrganizations(organizationsListReadRoles, h.countOrganizations))
	mux.HandleFunc("POST /admin/realms/{realm}/organizations",
		h.guardOrganizations(organizationWriteRoles, h.createOrganization))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}",
		h.guardOrganization(organizationReadRoles, h.readOrganization))
	mux.HandleFunc("PUT /admin/realms/{realm}/organizations/{orgID}",
		h.guardOrganization(organizationWriteRoles, h.updateOrganization))
	mux.HandleFunc("DELETE /admin/realms/{realm}/organizations/{orgID}",
		h.guardOrganization(organizationWriteRoles, h.deleteOrganization))

	// Organizations, the second cut: members, invitations and the identity
	// providers an organization owns. Nineteen operations, and **not one of
	// them is opened by a single role**.
	//
	// Measured 2026-09-02 with a token minted per caller, one user per role
	// set, against every route in the family. Four shapes:
	//
	//	the member reads      (view|manage-organizations|manage-realm) AND (view|manage|query-users)
	//	the member sub-reads  the same, minus query-users
	//	the member writes     (manage-organizations|manage-realm)      AND manage-users
	//	the broker family     (view|manage-organizations|manage-realm) AND (view|manage-identity-providers)
	//	the broker writes     (manage-organizations|manage-realm)      AND manage-identity-providers
	//	the invitations       (manage-organizations|manage-realm)      and no second family at all
	//
	// The last of those is the finding: **the invitation reads refuse the view
	// role**, which AGENTS.md records happening on exactly two routes in the
	// whole API before this.
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/members",
		h.guardOrganizationAnd(organizationReadRoles, organizationMemberListRoles, h.listOrganizationMembers))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/members/count",
		h.guardOrganizationAnd(organizationReadRoles, organizationMemberListRoles, h.countOrganizationMembers))
	mux.HandleFunc("POST /admin/realms/{realm}/organizations/{orgID}/members",
		h.guardOrganizationAnd(organizationWriteRoles, organizationMemberWriteRoles, h.addOrganizationMember))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/members/{memberID}",
		h.guardOrganizationAnd(organizationReadRoles, organizationMemberReadRoles, h.readOrganizationMember))
	mux.HandleFunc("DELETE /admin/realms/{realm}/organizations/{orgID}/members/{memberID}",
		h.guardOrganizationAnd(organizationWriteRoles, organizationMemberWriteRoles, h.removeOrganizationMember))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/members/{memberID}/groups",
		h.guardOrganizationAnd(organizationReadRoles, organizationMemberReadRoles, h.listOrganizationMemberGroups))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/members/{memberID}/organizations",
		h.guardOrganizationAnd(organizationReadRoles, organizationMemberReadRoles, h.listOrganizationMemberOrganizations))
	mux.HandleFunc("POST /admin/realms/{realm}/organizations/{orgID}/members/invite-user",
		h.guardOrganizationAnd(organizationWriteRoles, organizationMemberWriteRoles, h.inviteOrganizationUser))
	mux.HandleFunc("POST /admin/realms/{realm}/organizations/{orgID}/members/invite-existing-user",
		h.guardOrganizationAnd(organizationWriteRoles, organizationMemberWriteRoles, h.inviteExistingOrganizationUser))

	// **`GET /organizations/members/{member-id}/organizations` is the one
	// operation of this cut that is not served, and the reason is Go's
	// ServeMux rather than anything about Keycloak.**
	//
	// It and `GET /organizations/{orgID}/members/{memberID}` above are both
	// four segments, and they overlap on exactly one concrete path -
	// `/organizations/members/members/organizations`. Neither matches a strict
	// subset of the other, so `net/http` calls them conflicting and panics at
	// registration. Registering the overlap as a third, fully literal pattern
	// does **not** resolve it: `conflictsWith` is pairwise and knows nothing
	// about a third pattern, checked against Go 1.26.6 rather than inferred
	// from the documentation, which reads as though it might.
	//
	// The two ways out both cost more than the route is worth. A dispatcher on
	// `organizations/{a}/{b}/{c}` would swallow every four-segment path under
	// the tag that Gloak does not serve - the eleven F120 group routes among
	// them - and those answer the unmatched-path 404 **with none of the five
	// security headers**, which only WithKeycloakFallbacks can produce; a
	// handler writing that body itself would get the headers wrong. Dropping
	// the org-scoped read instead loses a route that matters more.
	//
	// Keycloak's own answers to the overlap are measured, so the next cut needs
	// no container:
	//
	//	/organizations/members/members/organizations  404 {"error":"HTTP 404 Not Found"}
	//	/organizations/members/members                404 {"errorMessage":"Organization not found."}
	//
	// The first is the top-level route reading `members` as a user id that
	// resolves to nothing; the second is the org-scoped route reading it as an
	// organization id. So JAX-RS prefers the literal segment on the
	// four-segment shape and the wildcard on the three-segment one.
	//
	// Its guard is measured too, and it is **not** its org-scoped twin's:
	// `query-organizations` opens it and is 403 on the other, while
	// `query-users` opens neither. Two routes serving byte-identical bodies,
	// two role sets.

	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/identity-providers",
		h.guardOrganizationAnd(organizationReadRoles, identityProviderReadRoles, h.listOrganizationIdentityProviders))
	mux.HandleFunc("POST /admin/realms/{realm}/organizations/{orgID}/identity-providers",
		h.guardOrganizationAnd(organizationWriteRoles, identityProviderWriteRoles, h.addOrganizationIdentityProvider))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/identity-providers/{idpAlias}",
		h.guardOrganizationAnd(organizationReadRoles, identityProviderReadRoles, h.readOrganizationIdentityProvider))
	mux.HandleFunc("DELETE /admin/realms/{realm}/organizations/{orgID}/identity-providers/{idpAlias}",
		h.guardOrganizationAnd(organizationWriteRoles, identityProviderWriteRoles, h.removeOrganizationIdentityProvider))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/identity-providers/{idpAlias}/groups",
		h.guardOrganizationAnd(organizationReadRoles, identityProviderReadRoles, h.listOrganizationIdentityProviderGroups))

	// Organizations, the third cut: an organization's groups and their role
	// mappings. Twenty-two operations, and **twenty of them are opened by a
	// single role** - which is the previous cut's rule inverted, not extended.
	//
	// Measured 2026-09-03 with a token minted per caller, one user per role
	// set, against every one of the twenty-two:
	//
	//	the reads over groups     (view|manage-organizations|manage-realm)
	//	the writes over groups    (manage-organizations|manage-realm)
	//	GET .../groups/{g}/members            the read pair AND (view|manage|query-users)
	//	PUT/DELETE .../members/{userID}       the write pair AND manage-users
	//
	// So `manage-organizations` alone opens nineteen routes here and was 403 on
	// every route of the member family. `query-organizations` and
	// `query-groups` open nothing at all, and `view-realm`, `view-clients` and
	// `manage-clients` reach nothing.
	//
	// **`group-by-path` has no pattern of its own**, and the reason is Go's
	// ServeMux rather than anything about Keycloak:
	// `.../groups/group-by-path/{path...}` conflicts with every deeper pattern
	// under `{groupID}` - `children`, `members`, `role-mappings` and its five
	// descendants - because `/groups/group-by-path/children` matches both and
	// neither is a strict subset of the other. Checked against Go 1.26.6 by
	// registering the intended set one pattern at a time: **eight** panics,
	// which is F153's shape and eight times its size. A single-segment `{path}`
	// does not help, and the measured paths are multi-segment anyway. The
	// literal is read in readOrganizationGroup instead, which is the one place
	// the two can be told apart without asking the router to decide.
	// TestOrganizationGroupRoutesRegister is what keeps that honest.
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/groups",
		h.guardOrganization(organizationReadRoles, h.listOrganizationGroups))
	mux.HandleFunc("POST /admin/realms/{realm}/organizations/{orgID}/groups",
		h.guardOrganization(organizationWriteRoles, h.createOrganizationGroup))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}",
		h.guardOrganization(organizationReadRoles, h.readOrganizationGroup))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/{rest...}",
		h.guardOrganization(organizationReadRoles, h.readOrganizationGroupTail))
	mux.HandleFunc("PUT /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}",
		h.guardOrganizationGroupOf(organizationWriteRoles, h.updateOrganizationGroup))
	mux.HandleFunc("DELETE /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}",
		h.guardOrganizationGroupOf(organizationWriteRoles, h.deleteOrganizationGroup))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/children",
		h.guardOrganizationGroupOf(organizationReadRoles, h.listOrganizationGroupChildren))
	mux.HandleFunc("POST /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/children",
		h.guardOrganizationGroupOf(organizationWriteRoles, h.createOrganizationGroupChild))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/members",
		h.guardOrganizationGroupOf(organizationMemberListRoles, h.listOrganizationGroupMembers))
	mux.HandleFunc("PUT /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/members/{userID}",
		h.guardOrganizationGroupOf(organizationWriteRoles, h.joinOrganizationGroup))
	mux.HandleFunc("DELETE /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/members/{userID}",
		h.guardOrganizationGroupOf(organizationWriteRoles, h.leaveOrganizationGroup))

	// The eleven role mappings of an organization group. **The handlers are
	// groupmappings.go's, unchanged, and the guard is not.**
	//
	// That the user and group locators already agree does not establish a
	// third, so the whole family was re-measured on this one: `{}` for a holder
	// with nothing, `Client not found` for an unknown client uuid,
	// `Role not found` for an unknown role in the array, `unknown_error` /
	// `Cannot parse the JSON` for a malformed body, briefRepresentation
	// honoured by `.../composite` alone, and the caller-relative rules intact -
	// a manage-organizations caller reads `.../available` on realm-management
	// as `[]` and is refused `manage-realm` on the write, where the same caller
	// holding manage-users too sees the nine roles its own roles confer. All of
	// it agrees with the two locators this project already serves.
	//
	// What does not agree is the guard - these take the organization roles,
	// where the realm group family's take view-users/manage-users - and the
	// 404, which is `Group does not exist` rather than
	// `Could not find group by id`.
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/role-mappings",
		h.guardOrganizationGroup(organizationReadRoles, h.allGroupMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/role-mappings/realm",
		h.guardOrganizationGroup(organizationReadRoles, h.listGroupRealmMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/role-mappings/realm/available",
		h.guardOrganizationGroup(organizationReadRoles, h.availableGroupRealmMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/role-mappings/realm/composite",
		h.guardOrganizationGroup(organizationReadRoles, h.compositeGroupRealmMappings))
	mux.HandleFunc("POST /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/role-mappings/realm",
		h.guardOrganizationGroup(organizationWriteRoles, h.assignGroupRealmMappings))
	mux.HandleFunc("DELETE /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/role-mappings/realm",
		h.guardOrganizationGroup(organizationWriteRoles, h.removeGroupRealmMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/role-mappings/clients/{clientUUID}",
		h.guardOrganizationGroup(organizationReadRoles, h.listGroupClientMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/role-mappings/clients/{clientUUID}/available",
		h.guardOrganizationGroup(organizationReadRoles, h.availableGroupClientMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/role-mappings/clients/{clientUUID}/composite",
		h.guardOrganizationGroup(organizationReadRoles, h.compositeGroupClientMappings))
	mux.HandleFunc("POST /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/role-mappings/clients/{clientUUID}",
		h.guardOrganizationGroup(organizationWriteRoles, h.assignGroupClientMappings))
	mux.HandleFunc("DELETE /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}/role-mappings/clients/{clientUUID}",
		h.guardOrganizationGroup(organizationWriteRoles, h.removeGroupClientMappings))

	// The invitations take one family and it is the **write** pair, on all four
	// operations including the two reads.
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/invitations",
		h.guardOrganization(organizationWriteRoles, h.listOrganizationInvitations))
	mux.HandleFunc("GET /admin/realms/{realm}/organizations/{orgID}/invitations/{invitationID}",
		h.guardOrganization(organizationWriteRoles, h.readOrganizationInvitation))
	mux.HandleFunc("DELETE /admin/realms/{realm}/organizations/{orgID}/invitations/{invitationID}",
		h.guardOrganization(organizationWriteRoles, h.deleteOrganizationInvitation))
	mux.HandleFunc("POST /admin/realms/{realm}/organizations/{orgID}/invitations/{invitationID}/resend",
		h.guardOrganization(organizationWriteRoles, h.resendOrganizationInvitation))

	// Authorization services. Twenty-nine operations of the description's
	// thirty-one untagged ones - the resource server as a resource, the two
	// provider catalogues, the scope family, the resource family, the policy
	// and permission families' three representations each and `import`. The two
	// left are `POST .../policy/evaluate` and `POST .../permission/evaluate`.
	// See docs/superpowers/plans/2026-08-31-p10-authz-services.md,
	// docs/superpowers/plans/2026-08-31-p10-authz-cut-b.md,
	// docs/superpowers/plans/2026-09-01-p10-authz-resources.md and
	// docs/superpowers/plans/2026-09-02-p10-authz-policies.md.
	//
	// **Every one of them sits behind the client's own
	// authorizationServicesEnabled**, and guardAuthz checks it *before* the
	// roles - client-types' order and not organizations'. See guardAuthz for
	// the six-row table this expresses.
	//
	// The two provider catalogues are the same handler twice because the two
	// responses are byte-identical, verified with cmp rather than assumed from
	// the names.
	const authzPrefix = "/admin/realms/{realm}/clients/{clientUUID}/authz/resource-server"
	mux.HandleFunc("GET "+authzPrefix, h.guardAuthz(authzReadRoles, h.readResourceServer))
	mux.HandleFunc("PUT "+authzPrefix, h.guardAuthz(authzWriteRoles, h.updateResourceServer))
	// **The settings read takes the write set**, measured: view-clients and
	// view-authorization both read the route above and are 403 on this one. It
	// is a read that refuses the view role, which is the inverse of AGENTS.md's
	// "reads accept the manage role, not just the view role" - so the list is
	// written out here rather than shared with the read.
	mux.HandleFunc("GET "+authzPrefix+"/settings", h.guardAuthz(authzWriteRoles, h.readResourceServerSettings))
	mux.HandleFunc("GET "+authzPrefix+"/policy/providers", h.guardAuthz(authzReadRoles, h.listPolicyProviders))
	mux.HandleFunc("GET "+authzPrefix+"/permission/providers", h.guardAuthz(authzReadRoles, h.listPolicyProviders))

	// The scope family, eight operations. The role sets are the two above and
	// were **re-measured** on this family rather than carried over: seven
	// callers, one single role each, on all eight routes. They came back
	// identical - the five reads take authzReadRoles and the three writes
	// authzWriteRoles, with query-clients and manage-realm 403 on every one.
	// A role set carried over from a neighbouring family has been wrong four
	// times in this repository, so agreeing was the finding rather than the
	// assumption.
	//
	// `/scope/search` is registered beside `/scope/{scopeID}` and the mux
	// prefers the literal, which is what makes `search` reachable at all.
	mux.HandleFunc("GET "+authzPrefix+"/scope", h.guardAuthz(authzReadRoles, h.listAuthzScopes))
	mux.HandleFunc("POST "+authzPrefix+"/scope", h.guardAuthz(authzWriteRoles, h.createAuthzScope))
	mux.HandleFunc("GET "+authzPrefix+"/scope/search", h.guardAuthz(authzReadRoles, h.searchAuthzScope))
	mux.HandleFunc("GET "+authzPrefix+"/scope/{scopeID}", h.guardAuthz(authzReadRoles, h.readAuthzScope))
	mux.HandleFunc("PUT "+authzPrefix+"/scope/{scopeID}", h.guardAuthz(authzWriteRoles, h.updateAuthzScope))
	mux.HandleFunc("DELETE "+authzPrefix+"/scope/{scopeID}", h.guardAuthz(authzWriteRoles, h.deleteAuthzScope))
	mux.HandleFunc("GET "+authzPrefix+"/scope/{scopeID}/permissions",
		h.guardAuthz(authzReadRoles, h.listAuthzScopePermissions))
	mux.HandleFunc("GET "+authzPrefix+"/scope/{scopeID}/resources",
		h.guardAuthz(authzReadRoles, h.listAuthzScopeResources))

	// The resource family, nine operations. The role sets are the two above,
	// re-measured on this family one single role at a time over eight callers
	// - `none`, the two authorization roles, the three client roles,
	// `manage-realm` and `view-users`. They came back identical to the scope
	// family's: the six reads take authzReadRoles and the three writes
	// authzWriteRoles, with `query-clients`, `manage-realm` and `view-users`
	// 403 on every one. Agreeing was the finding rather than the assumption,
	// which is the second time this family has been swept rather than trusted.
	//
	// **The role check precedes the resource lookup**, measured:
	// `DELETE .../resource/{unknown}` is 403 to a `view-authorization` caller
	// and 404 to a `manage-authorization` one.
	//
	// `/resource/search` is registered beside `/resource/{resourceID}` and the
	// mux prefers the literal, which is what makes `search` reachable at all -
	// the scope family's arrangement one path segment along.
	mux.HandleFunc("GET "+authzPrefix+"/resource",
		h.guardAuthz(authzReadRoles, h.listAuthzResources))
	mux.HandleFunc("POST "+authzPrefix+"/resource",
		h.guardAuthz(authzWriteRoles, h.createAuthzResource))
	mux.HandleFunc("GET "+authzPrefix+"/resource/search",
		h.guardAuthz(authzReadRoles, h.searchAuthzResource))
	mux.HandleFunc("GET "+authzPrefix+"/resource/{resourceID}",
		h.guardAuthz(authzReadRoles, h.readAuthzResource))
	mux.HandleFunc("PUT "+authzPrefix+"/resource/{resourceID}",
		h.guardAuthz(authzWriteRoles, h.updateAuthzResource))
	mux.HandleFunc("DELETE "+authzPrefix+"/resource/{resourceID}",
		h.guardAuthz(authzWriteRoles, h.deleteAuthzResource))
	mux.HandleFunc("GET "+authzPrefix+"/resource/{resourceID}/attributes",
		h.guardAuthz(authzReadRoles, h.readAuthzResourceAttributes))
	mux.HandleFunc("GET "+authzPrefix+"/resource/{resourceID}/permissions",
		h.guardAuthz(authzReadRoles, h.listAuthzResourcePermissions))
	mux.HandleFunc("GET "+authzPrefix+"/resource/{resourceID}/scopes",
		h.guardAuthz(authzReadRoles, h.listAuthzResourceScopes))

	// The policy and permission families, three operations each, and `import`.
	// The role sets are the two above, swept on all nine of the family's
	// remaining routes one single role at a time over seven callers - none, the
	// two authorization roles, the three client roles and manage-realm. They
	// came back identical to the scope and resource families': the four reads
	// take authzReadRoles and the two creates and `import` take
	// authzWriteRoles, with query-clients and manage-realm 403 on every one.
	// **Both `evaluate`s take the read set**, which is the one cell of that
	// sweep worth writing down, because a POST that runs the authorization
	// engine reads as a write.
	//
	// **The six policy and permission routes are three handlers, not six.** The
	// two listings, the two searches and the two creates were each measured
	// serving the same rows, and only the path decides the view and the family
	// filter - see authzTypedRoute. Registering six handlers would put one
	// measurement in two places, which is how the scope family's two orders got
	// written down twice and disagreed.
	//
	// `/policy/providers` and `/permission/providers` above are registered
	// ahead of nothing here: neither `/policy` nor `/permission` takes a
	// trailing segment in the description, so the literals cannot collide.
	mux.HandleFunc("GET "+authzPrefix+"/policy",
		h.guardAuthz(authzReadRoles, h.listAuthzPolicies))
	mux.HandleFunc("POST "+authzPrefix+"/policy",
		h.guardAuthz(authzWriteRoles, h.createAuthzPolicy))
	mux.HandleFunc("GET "+authzPrefix+"/policy/search",
		h.guardAuthz(authzReadRoles, h.searchAuthzPolicy))
	mux.HandleFunc("GET "+authzPrefix+"/permission",
		h.guardAuthz(authzReadRoles, h.listAuthzPolicies))
	mux.HandleFunc("POST "+authzPrefix+"/permission",
		h.guardAuthz(authzWriteRoles, h.createAuthzPolicy))
	mux.HandleFunc("GET "+authzPrefix+"/permission/search",
		h.guardAuthz(authzReadRoles, h.searchAuthzPolicy))
	mux.HandleFunc("POST "+authzPrefix+"/import",
		h.guardAuthz(authzWriteRoles, h.importAuthzSettings))

	// The twelve `management/permissions` operations. All of them are the same
	// 501, and they need **three** combinators because the refusal does not sit
	// at one point relative to the resource the path names. The reason each is
	// what it is lives in managementpermissions.go; the short version is that
	// the two tagged Groups and the four tagged Clients resolve their resource
	// first and the other six never look theirs up at all.
	for _, path := range []string{
		"/admin/realms/{realm}/roles/{roleName}/management/permissions",
		"/admin/realms/{realm}/roles-by-id/{roleID}/management/permissions",
		"/admin/realms/{realm}/identity-provider/instances/{alias}/management/permissions",
	} {
		mux.HandleFunc("GET "+path, h.guardRealmFeature(h.managementPermissions))
		mux.HandleFunc("PUT "+path, h.guardRealmFeature(h.managementPermissions))
	}
	for _, path := range []string{
		"/admin/realms/{realm}/clients/{clientUUID}/management/permissions",
		"/admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/management/permissions",
	} {
		mux.HandleFunc("GET "+path, h.guardClientFeature(h.managementPermissions))
		mux.HandleFunc("PUT "+path, h.guardClientFeature(h.managementPermissions))
	}
	mux.HandleFunc("GET /admin/realms/{realm}/groups/{groupID}/management/permissions",
		h.guardGroupResolving(h.managementPermissionsAfterGroup))
	mux.HandleFunc("PUT /admin/realms/{realm}/groups/{groupID}/management/permissions",
		h.guardGroupResolving(h.managementPermissionsAfterGroup))

	// Identity Providers. Counting the two `management/permissions` operations
	// registered above, this tag is now **every operation the description lists
	// except `import-config`**, which is unbuilt because it makes an outbound
	// HTTP fetch from this package - a boundary decision rather than a detail.
	// See docs/superpowers/plans/2026-09-01-p9-identity-providers.md for the
	// routes below and 2026-09-02-p9-provider-catalogue.md for the block after
	// them.
	//
	// **The gate is a fifth shape and it is the simplest of the five**: a plain
	// two-role check with no feature flag, no realm flag and no resource
	// resolved in front of it. Measured one role at a time over sixteen
	// callers - the whole family answers 403 to every role outside the
	// identity-provider pair, `view-clients` and `manage-realm` included.
	//
	// **The alias is resolved after the roles**: a DELETE of an alias that does
	// not exist is 403 to a `view-identity-providers` caller and 404 to a
	// `manage-identity-providers` one. That is the `default-*-client-scopes`
	// order and the opposite of the Groups tag's, whose routes answer 404 to a
	// caller holding nothing.
	const idpPrefix = "/admin/realms/{realm}/identity-provider/instances"
	mux.HandleFunc("GET "+idpPrefix,
		h.guardAny(identityProviderReadRoles, h.listIdentityProviders))
	mux.HandleFunc("POST "+idpPrefix,
		h.guardAny(identityProviderWriteRoles, h.createIdentityProvider))
	mux.HandleFunc("GET "+idpPrefix+"/{alias}",
		h.guardIdentityProvider(identityProviderReadRoles, h.readIdentityProvider))
	// **The update resolves nothing**, deliberately: its strict decode runs
	// *before* the path's alias, measured - a PUT to an alias that does not
	// exist carrying an unknown field answers the 400 and not the 404. That is
	// the required-action PUT's order and the opposite of the organization
	// PUT's, so the handler does its own lookup after decoding.
	mux.HandleFunc("PUT "+idpPrefix+"/{alias}",
		h.guardAny(identityProviderWriteRoles, h.updateIdentityProvider))
	mux.HandleFunc("DELETE "+idpPrefix+"/{alias}",
		h.guardIdentityProvider(identityProviderWriteRoles, h.deleteIdentityProvider))
	mux.HandleFunc("GET "+idpPrefix+"/{alias}/export",
		h.guardIdentityProvider(identityProviderReadRoles, h.exportIdentityProvider))
	// **reload-keys takes the write set although it is a GET.** Measured one
	// role at a time: `view-identity-providers` reads the six routes above and
	// is 403 here. It is the second read in this API with that shape, after
	// `GET .../authz/resource-server/settings`, and the list is written out
	// rather than shared for the reason that one's is.
	mux.HandleFunc("GET "+idpPrefix+"/{alias}/reload-keys",
		h.guardIdentityProvider(identityProviderWriteRoles, h.reloadIdentityProviderKeys))

	// P9's second cut: the property catalogue and the five mapper operations.
	// See docs/superpowers/plans/2026-09-02-p9-provider-catalogue.md.
	//
	// **The guards are the first cut's two, re-measured on all seven rather
	// than inherited.** One role at a time over six callers: the four reads
	// take `view-identity-providers` or `manage-identity-providers` and the
	// three writes take `manage-identity-providers` alone. `view-realm` and
	// `manage-realm` are 403 on every one of them, and `view-clients` is the
	// control.
	//
	// `providers/{provider_id}` is the one route of the seven with no instance
	// in its path, so it takes the plain role guard.
	mux.HandleFunc("GET /admin/realms/{realm}/identity-provider/providers/{providerID}",
		h.guardAny(identityProviderReadRoles, h.readIdentityProviderInfo))
	mux.HandleFunc("GET "+idpPrefix+"/{alias}/mapper-types",
		h.guardIdentityProvider(identityProviderReadRoles, h.listIdentityProviderMapperTypes))
	mux.HandleFunc("GET "+idpPrefix+"/{alias}/mappers",
		h.guardIdentityProvider(identityProviderReadRoles, h.listIdentityProviderMappers))
	mux.HandleFunc("POST "+idpPrefix+"/{alias}/mappers",
		h.guardIdentityProvider(identityProviderWriteRoles, h.createIdentityProviderMapper))
	mux.HandleFunc("GET "+idpPrefix+"/{alias}/mappers/{mapperID}",
		h.guardIdentityProvider(identityProviderReadRoles, h.readIdentityProviderMapper))
	mux.HandleFunc("PUT "+idpPrefix+"/{alias}/mappers/{mapperID}",
		h.guardIdentityProvider(identityProviderWriteRoles, h.updateIdentityProviderMapper))
	mux.HandleFunc("DELETE "+idpPrefix+"/{alias}/mappers/{mapperID}",
		h.guardIdentityProvider(identityProviderWriteRoles, h.deleteIdentityProviderMapper))

	// Component, all six.
	//
	// **The family is authorised out of the realm role set**, although its rows
	// are key providers and client-registration policies:
	// `manage-identity-providers` is 403 on both routes and `view-realm` reads
	// them. That is the third time the description's tag has failed to predict
	// the guard, and the neighbouring family in this very commit takes the
	// other pair.
	//
	// **The role is judged before the component is resolved, per verb.** A
	// `view-realm` caller naming a component that does not exist gets 404 on the
	// `GET` and 403 on the `PUT` and the `DELETE`, where a `manage-realm` caller
	// gets 404 on all three - measured, and it is guardAny's own order rather
	// than anything this family had to be given.
	mux.HandleFunc("GET /admin/realms/{realm}/components",
		h.guardAny(componentReadRoles, h.listComponents))
	mux.HandleFunc("POST /admin/realms/{realm}/components",
		h.guardAny(componentWriteRoles, h.createComponent))
	mux.HandleFunc("GET /admin/realms/{realm}/components/{componentID}",
		h.guardAny(componentReadRoles, h.readComponent))
	mux.HandleFunc("PUT /admin/realms/{realm}/components/{componentID}",
		h.guardAny(componentWriteRoles, h.updateComponent))
	mux.HandleFunc("DELETE /admin/realms/{realm}/components/{componentID}",
		h.guardAny(componentWriteRoles, h.deleteComponent))
	mux.HandleFunc("GET /admin/realms/{realm}/components/{componentID}/sub-component-types",
		h.guardAny(componentReadRoles, h.listSubComponentTypes))

	// Attack Detection, all three. **Authorised out of the users pair**, which
	// nothing in the path or the tag says: the read takes `view-users` or
	// `manage-users` and the two deletes take `manage-users` alone, which is the
	// role-mapping family's shape exactly. `query-users`, which opens
	// `GET /users`, is 403 on all three.
	mux.HandleFunc("GET /admin/realms/{realm}/attack-detection/brute-force/users/{userID}",
		h.guardAny(bruteForceReadRoles, h.readBruteForceStatus))
	mux.HandleFunc("DELETE /admin/realms/{realm}/attack-detection/brute-force/users/{userID}",
		h.guardAny(bruteForceWriteRoles, h.clearBruteForceForUser))
	mux.HandleFunc("DELETE /admin/realms/{realm}/attack-detection/brute-force/users",
		h.guardAny(bruteForceWriteRoles, h.clearBruteForceForRealm))

	// Client Initial Access, all three. **Authorised out of the clients pair** -
	// `view-realm` and `manage-realm` are 403 on all three - so this branch adds
	// one family on each of the API's two commonest role pairs and the
	// description's tags predict neither.
	mux.HandleFunc("GET /admin/realms/{realm}/clients-initial-access",
		h.guardAny(initialAccessReadRoles, h.listClientInitialAccess))
	mux.HandleFunc("POST /admin/realms/{realm}/clients-initial-access",
		h.guardAny(initialAccessWriteRoles, h.createClientInitialAccess))
	mux.HandleFunc("DELETE /admin/realms/{realm}/clients-initial-access/{initialAccessID}",
		h.guardAny(initialAccessWriteRoles, h.deleteClientInitialAccess))

	// Authentication Management, the eighteen operations of P8's first cut.
	// The other twenty-one - the flows, the executions and the shared
	// authenticator config - are not here, and that is a decision rather than
	// an omission: Gloak walks a hard-coded browser flow, so serving the
	// routes that edit a stored one would move state nothing consumes. See
	// docs/superpowers/plans/2026-08-30-p8-authentication.md section 0.
	//
	// The SPI registry: six read-only operations off one embedded table. They
	// take the realm's read pair, measured across all 21 roles of the realm's
	// own container.
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/authenticator-providers",
		h.guardAny(realmConfigReadRoles, h.listAuthenticatorProviders))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/client-authenticator-providers",
		h.guardAny(realmConfigReadRoles, h.listClientAuthenticatorProviders))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/form-action-providers",
		h.guardAny(realmConfigReadRoles, h.listFormActionProviders))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/form-providers",
		h.guardAny(realmConfigReadRoles, h.listFormProviders))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/per-client-config-description",
		h.guardAny(realmConfigReadRoles, h.readPerClientConfigDescription))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/config-description/{providerID}",
		h.guardAny(realmConfigReadRoles, h.readAuthenticatorConfigDescription))

	// The required actions. Every route here takes the realm's pair to read and
	// manage-realm to write - **except the listing**, which is measurably
	// wider: view-users and query-users get a 200 on it and a 403 on every one
	// of its siblings, with a byte-identical body. One tag, three role sets.
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/required-actions",
		h.guardAny(requiredActionsListReadRoles, h.listRequiredActions))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/unregistered-required-actions",
		h.guardAny(realmConfigReadRoles, h.listUnregisteredRequiredActions))
	mux.HandleFunc("POST /admin/realms/{realm}/authentication/register-required-action",
		h.guardAny(realmWriteRoles, h.registerRequiredAction))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/required-actions/{alias}",
		h.guardAny(realmConfigReadRoles, h.readRequiredAction))
	mux.HandleFunc("PUT /admin/realms/{realm}/authentication/required-actions/{alias}",
		h.guardAny(realmWriteRoles, h.updateRequiredAction))
	mux.HandleFunc("DELETE /admin/realms/{realm}/authentication/required-actions/{alias}",
		h.guardAny(realmWriteRoles, h.deleteRequiredAction))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/required-actions/{alias}/config",
		h.guardAny(realmConfigReadRoles, h.readRequiredActionConfig))
	mux.HandleFunc("PUT /admin/realms/{realm}/authentication/required-actions/{alias}/config",
		h.guardAny(realmWriteRoles, h.updateRequiredActionConfig))
	mux.HandleFunc("DELETE /admin/realms/{realm}/authentication/required-actions/{alias}/config",
		h.guardAny(realmWriteRoles, h.deleteRequiredActionConfig))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/required-actions/{alias}/config-description",
		h.guardAny(realmConfigReadRoles, h.readRequiredActionConfigDescription))
	mux.HandleFunc("POST /admin/realms/{realm}/authentication/required-actions/{alias}/raise-priority",
		h.guardAny(realmWriteRoles, h.raiseRequiredActionPriority))
	mux.HandleFunc("POST /admin/realms/{realm}/authentication/required-actions/{alias}/lower-priority",
		h.guardAny(realmWriteRoles, h.lowerRequiredActionPriority))

	// The flow model, twenty-one operations. GET /flows takes its own wider
	// slice and every other read on the family takes realmConfigReadRoles -
	// measured one role at a time, and view-clients is a 403 on
	// GET /flows/{id} one segment away from the 200 it gets here.
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/flows",
		h.guardAny(flowListReadRoles, h.listFlows))
	mux.HandleFunc("POST /admin/realms/{realm}/authentication/flows",
		h.guardAny(realmWriteRoles, h.createFlow))
	mux.HandleFunc("POST /admin/realms/{realm}/authentication/flows/{flowAlias}/copy",
		h.guardAny(realmWriteRoles, h.copyFlow))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/flows/{flowAlias}/executions",
		h.guardAny(realmConfigReadRoles, h.listFlowExecutions))
	mux.HandleFunc("PUT /admin/realms/{realm}/authentication/flows/{flowAlias}/executions",
		h.guardAny(realmWriteRoles, h.updateFlowExecution))
	mux.HandleFunc("POST /admin/realms/{realm}/authentication/flows/{flowAlias}/executions/execution",
		h.guardAny(realmWriteRoles, h.createFlowExecution))
	mux.HandleFunc("POST /admin/realms/{realm}/authentication/flows/{flowAlias}/executions/flow",
		h.guardAny(realmWriteRoles, h.createSubFlow))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/flows/{id}",
		h.guardAny(realmConfigReadRoles, h.readFlow))
	mux.HandleFunc("PUT /admin/realms/{realm}/authentication/flows/{id}",
		h.guardAny(realmWriteRoles, h.updateFlow))
	mux.HandleFunc("DELETE /admin/realms/{realm}/authentication/flows/{id}",
		h.guardAny(realmWriteRoles, h.deleteFlow))
	mux.HandleFunc("POST /admin/realms/{realm}/authentication/executions",
		h.guardAny(realmWriteRoles, h.createExecution))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/executions/{executionId}",
		h.guardAny(realmConfigReadRoles, h.readExecution))
	mux.HandleFunc("DELETE /admin/realms/{realm}/authentication/executions/{executionId}",
		h.guardAny(realmWriteRoles, h.deleteExecution))
	mux.HandleFunc("POST /admin/realms/{realm}/authentication/executions/{executionId}/config",
		h.guardAny(realmWriteRoles, h.createExecutionConfig))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/executions/{executionId}/config/{id}",
		h.guardAny(realmConfigReadRoles, h.readExecutionConfig))
	mux.HandleFunc("POST /admin/realms/{realm}/authentication/executions/{executionId}/raise-priority",
		h.guardAny(realmWriteRoles, h.raiseExecutionPriority))
	mux.HandleFunc("POST /admin/realms/{realm}/authentication/executions/{executionId}/lower-priority",
		h.guardAny(realmWriteRoles, h.lowerExecutionPriority))
	mux.HandleFunc("POST /admin/realms/{realm}/authentication/config",
		h.guardAny(realmWriteRoles, h.createConfig))
	mux.HandleFunc("GET /admin/realms/{realm}/authentication/config/{id}",
		h.guardAny(realmConfigReadRoles, h.readConfig))
	mux.HandleFunc("PUT /admin/realms/{realm}/authentication/config/{id}",
		h.guardAny(realmWriteRoles, h.updateConfig))
	mux.HandleFunc("DELETE /admin/realms/{realm}/authentication/config/{id}",
		h.guardAny(realmWriteRoles, h.deleteConfig))

	// Listing and counting accept query-users as well as view-users, measured:
	// a caller holding only query-users gets 200 on both. Reading one user
	// does not - it answers 403.
	mux.HandleFunc("GET /admin/realms/{realm}/users", h.guardAny(usersReadRoles, h.listUsers))
	mux.HandleFunc("GET /admin/realms/{realm}/users/count", h.guardAny(usersReadRoles, h.countUsers))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}", h.guardUserSubject(userReadRoles, h.readUser))
	mux.HandleFunc("POST /admin/realms/{realm}/users", h.guard("manage-users", h.createUser))
	mux.HandleFunc("PUT /admin/realms/{realm}/users/{userID}", h.guardUserSubject(userWriteRoles, h.updateUser))
	mux.HandleFunc("DELETE /admin/realms/{realm}/users/{userID}", h.guardUserSubject(userWriteRoles, h.deleteUser))
	// Reading a credential list needs only view-users: the body carries no
	// secret. Everything that changes one needs manage-users.
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/credentials", h.guardUserSubject(userReadRoles, h.listCredentials))
	mux.HandleFunc("PUT /admin/realms/{realm}/users/{userID}/reset-password", h.guardUserSubject(userWriteRoles, h.resetPassword))
	mux.HandleFunc("DELETE /admin/realms/{realm}/users/{userID}/credentials/{credentialID}", h.guardUserSubject(userWriteRoles, h.deleteCredential))
	mux.HandleFunc("PUT /admin/realms/{realm}/users/{userID}/credentials/{credentialID}/userLabel", h.guardUserSubject(userWriteRoles, h.setCredentialLabel))
	mux.HandleFunc("POST /admin/realms/{realm}/users/{userID}/credentials/{credentialID}/moveToFirst", h.guardUserSubject(userWriteRoles, h.moveCredentialToFirst))
	mux.HandleFunc("POST /admin/realms/{realm}/users/{userID}/credentials/{credentialID}/moveAfter/{previousID}", h.guardUserSubject(userWriteRoles, h.moveCredentialAfter))
	mux.HandleFunc("PUT /admin/realms/{realm}/users/{userID}/disable-credential-types", h.guardUserSubject(userWriteRoles, h.disableCredentialTypes))
	mux.HandleFunc("POST /admin/realms/{realm}/users/{userID}/logout", h.guardUserSubject(userWriteRoles, h.logoutUser))

	// The user half of the session family. Both take userReadRoles - the
	// *read* pair, where the logout one line above takes the write role - so
	// the family's two reads and its one write split the way the rest of this
	// tag does. Measured one role at a time; query-users opens neither.
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/sessions",
		h.guardUserSubject(userReadRoles, h.userSessions))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/offline-sessions/{clientUUID}",
		h.guardUserSubject(userReadRoles, h.userOfflineSessions))

	// A user's group membership. Same combinator and same role sets as the
	// rest of the user family, which is what the sweep says: the coarse gate
	// is usersReadRoles - query-users opens none of these four and still gets
	// the 404 for a user that does not exist - and the group is resolved
	// **inside the handler**, after the role check.
	//
	// That is the opposite order from the Groups routes below, which resolve
	// the group before judging anybody. Measured on both; see joinGroup.
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/groups",
		h.guardUserSubject(userReadRoles, h.listUserGroups))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/groups/count",
		h.guardUserSubject(userReadRoles, h.countUserGroups))
	mux.HandleFunc("PUT /admin/realms/{realm}/users/{userID}/groups/{groupID}",
		h.guardUserSubject(userWriteRoles, h.joinGroup))
	mux.HandleFunc("DELETE /admin/realms/{realm}/users/{userID}/groups/{groupID}",
		h.guardUserSubject(userWriteRoles, h.leaveGroup))

	// Groups. They are authorised out of the **users** family and not a family
	// of their own: manage-realm is 403 on every one of them, measured, and
	// view-users is what opens the reads.
	//
	// The six routes naming a {groupID} take guardGroup, which resolves the
	// group before judging the caller - see its doc comment for why that is not
	// the shape the neighbouring user routes take.
	mux.HandleFunc("GET /admin/realms/{realm}/groups", h.guardAny(groupsReadRoles, h.listGroups))
	mux.HandleFunc("GET /admin/realms/{realm}/groups/count", h.guardAny(groupsReadRoles, h.countGroups))
	mux.HandleFunc("POST /admin/realms/{realm}/groups", h.guard("manage-users", h.createGroup))
	mux.HandleFunc("GET /admin/realms/{realm}/groups/{groupID}", h.guardGroup(groupReadRoles, h.readGroup))
	mux.HandleFunc("PUT /admin/realms/{realm}/groups/{groupID}", h.guardGroup(groupWriteRoles, h.updateGroup))
	mux.HandleFunc("DELETE /admin/realms/{realm}/groups/{groupID}", h.guardGroup(groupWriteRoles, h.deleteGroup))
	mux.HandleFunc("GET /admin/realms/{realm}/groups/{groupID}/children", h.guardGroup(groupReadRoles, h.listChildren))
	mux.HandleFunc("POST /admin/realms/{realm}/groups/{groupID}/children", h.guardGroup(groupWriteRoles, h.createChild))
	mux.HandleFunc("GET /admin/realms/{realm}/groups/{groupID}/members", h.guardGroup(groupReadRoles, h.groupMembers))

	// A group's role mappings, the eleven of cut C. The roles are the user
	// mapping routes' - view-users or manage-users to read, manage-users to
	// write - and the **ordering** is this family's: guardGroup, so an unknown
	// group is 404 to every caller. Both halves measured on these routes
	// rather than carried over; see internal/admin/groupmappings.go.
	mux.HandleFunc("GET /admin/realms/{realm}/groups/{groupID}/role-mappings",
		h.guardGroup(userMappingsReadRoles, h.allGroupMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/groups/{groupID}/role-mappings/realm",
		h.guardGroup(userMappingsReadRoles, h.listGroupRealmMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/groups/{groupID}/role-mappings/realm/available",
		h.guardGroup(userMappingsReadRoles, h.availableGroupRealmMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/groups/{groupID}/role-mappings/realm/composite",
		h.guardGroup(userMappingsReadRoles, h.compositeGroupRealmMappings))
	mux.HandleFunc("POST /admin/realms/{realm}/groups/{groupID}/role-mappings/realm",
		h.guardGroup(userMappingsWriteRoles, h.assignGroupRealmMappings))
	mux.HandleFunc("DELETE /admin/realms/{realm}/groups/{groupID}/role-mappings/realm",
		h.guardGroup(userMappingsWriteRoles, h.removeGroupRealmMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/groups/{groupID}/role-mappings/clients/{clientUUID}",
		h.guardGroupClient(userMappingsReadRoles, h.listGroupClientMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/groups/{groupID}/role-mappings/clients/{clientUUID}/available",
		h.guardGroupClient(userMappingsReadRoles, h.availableGroupClientMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/groups/{groupID}/role-mappings/clients/{clientUUID}/composite",
		h.guardGroupClient(userMappingsReadRoles, h.compositeGroupClientMappings))
	mux.HandleFunc("POST /admin/realms/{realm}/groups/{groupID}/role-mappings/clients/{clientUUID}",
		h.guardGroupClient(userMappingsWriteRoles, h.assignGroupClientMappings))
	mux.HandleFunc("DELETE /admin/realms/{realm}/groups/{groupID}/role-mappings/clients/{clientUUID}",
		h.guardGroupClient(userMappingsWriteRoles, h.removeGroupClientMappings))

	// The combined view: both halves of a user's **direct** mappings in one
	// object. Same guard as the six listings below, and measured on this route
	// rather than inherited - the same seven single-role callers, a fresh token
	// minted immediately before each call. view-clients was the plausible one
	// on a body keyed by clientId, and it is 403 here like the other four.
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings",
		h.guardUserSubject(userMappingsReadRoles, h.allMappings))

	// A user's realm role mappings: three reads that answer three different
	// questions. All three take view-users or manage-users - measured against a
	// live 26.7.1 with one user per role, a fresh token minted immediately
	// before each call, and two different subjects.
	//
	// Not usersReadRoles, which is one role wider: query-users opens the user
	// listing and the count and is 403 on all three of these. And not
	// view-users alone, which the plan predicted: manage-users has no
	// composites at all - it is not composite over view-users - and still opens
	// every one of them, so refusing it would be the too-restrictive direction
	// this cut has already reverted twice.
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/realm",
		h.guardUserSubject(userMappingsReadRoles, h.listRealmMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/realm/available",
		h.guardUserSubject(userMappingsReadRoles, h.availableRealmMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/realm/composite",
		h.guardUserSubject(userMappingsReadRoles, h.compositeRealmMappings))

	// The two writes take manage-users **alone**, which is narrower than the
	// reads above - measured on both verbs across the same seven single-role
	// callers, with a fresh token minted immediately before each call.
	// view-users opens all three reads and neither write, so
	// userMappingsReadRoles must not be reused here; extending a rule measured
	// on one verb to its neighbour is what this cut has already had to revert
	// twice.
	//
	// The guard follows the **subject**, not the role: a caller holding
	// manage-realm and nothing else is refused even for a realm role, which is
	// the opposite of roles-by-id.
	mux.HandleFunc("POST /admin/realms/{realm}/users/{userID}/role-mappings/realm",
		h.guardUserSubject(userMappingsWriteRoles, h.assignRealmMappings))
	mux.HandleFunc("DELETE /admin/realms/{realm}/users/{userID}/role-mappings/realm",
		h.guardUserSubject(userMappingsWriteRoles, h.removeRealmMappings))

	// The same three reads for one client's roles. The guard is the realm
	// triple's, and that is measured on these routes rather than inherited:
	// the same seven single-role callers were swept against all three, on two
	// subjects and two containers, with a fresh token minted immediately
	// before each call. A client-scoped route plausibly wants view-clients,
	// and it does not - view-clients and manage-clients are 403 on all three,
	// like every other role outside the users family.
	//
	// The guard follows the **subject** here too: which client's roles are
	// being read makes no difference to it, which is why the {clientUUID}
	// segment is the handler's business and not the guard's.
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/clients/{clientUUID}",
		h.guardUserSubjectClient(userMappingsReadRoles, h.listClientMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/clients/{clientUUID}/available",
		h.guardUserSubjectClient(userMappingsReadRoles, h.availableClientMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/clients/{clientUUID}/composite",
		h.guardUserSubjectClient(userMappingsReadRoles, h.compositeClientMappings))

	// The two client writes take manage-users **alone** - the realm writes'
	// guard, and narrower than the client reads directly above, which
	// view-users opens. Measured on these routes across the same seven
	// single-role callers, on both verbs, on an ordinary client and on the
	// realm's own, with a fresh token minted immediately before each call.
	//
	// A client-scoped **write** is where manage-clients was most plausible -
	// the reads refusing it is evidence about reads only - and it is 403 here
	// too. The guard follows the subject on this pair as on every other one in
	// the family, so the {clientUUID} segment stays the handler's business.
	mux.HandleFunc("POST /admin/realms/{realm}/users/{userID}/role-mappings/clients/{clientUUID}",
		h.guardUserSubjectClient(userMappingsWriteRoles, h.assignClientMappings))
	mux.HandleFunc("DELETE /admin/realms/{realm}/users/{userID}/role-mappings/clients/{clientUUID}",
		h.guardUserSubjectClient(userMappingsWriteRoles, h.removeClientMappings))

	mux.HandleFunc("GET /admin/realms/{realm}/clients", h.guardAny(clientsReadRoles, h.listClients))
	// {clientUUID}, not {client-uuid}: net/http requires a wildcard name to be
	// a Go identifier and panics on the hyphen. The OpenAPI description spells
	// it with one, and Case.Operation keeps that spelling - the route pattern
	// is ours, the operation key is Keycloak's, and they are not the same
	// string.
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}", h.guard("view-clients", h.readClient))
	mux.HandleFunc("POST /admin/realms/{realm}/clients", h.guard("manage-clients", h.createClient))
	mux.HandleFunc("PUT /admin/realms/{realm}/clients/{clientUUID}", h.guard("manage-clients", h.updateClient))
	mux.HandleFunc("DELETE /admin/realms/{realm}/clients/{clientUUID}", h.guard("manage-clients", h.deleteClient))

	// Reading a secret needs view-clients and regenerating one needs
	// manage-clients. That split is measured, not read off the names: three
	// users were given exactly one master-realm role each and every operation
	// called with a token for them.
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/client-secret", h.guard("view-clients", h.readClientSecret))
	mux.HandleFunc("POST /admin/realms/{realm}/clients/{clientUUID}/client-secret", h.guard("manage-clients", h.regenerateClientSecret))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/client-secret/rotated", h.guard("view-clients", h.readRotatedSecret))
	mux.HandleFunc("DELETE /admin/realms/{realm}/clients/{clientUUID}/client-secret/rotated",
		h.guardRejecting("manage-clients", deleteRotatedSecretRejection, h.deleteRotatedSecret))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/service-account-user", h.guard("view-clients", h.readServiceAccountUser))

	// The client half of the session family. The four reads take view-clients
	// **or manage-clients** and push-revocation takes manage-clients alone -
	// measured one role at a time over eight candidates, and query-clients
	// opens none of the five.
	//
	// The read pair is clientRolesReadRoles rather than h.guard("view-clients")
	// deliberately, and the difference is measured: the four routes above that
	// take the single-role form refuse manage-clients where 26.7.1 answers
	// them 200. That is a divergence this cut found and did not fix, because
	// it belongs to the client chapter and no case pins it; see the handover.
	//
	// The two offline reads are served from the empty set and are guarded and
	// resolved in full; see internal/admin/sessions.go for why there is no
	// offline session table behind them.
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/session-count",
		h.guardAny(clientRolesReadRoles, h.clientSessionCount))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/user-sessions",
		h.guardAny(clientRolesReadRoles, h.clientUserSessions))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/offline-session-count",
		h.guardAny(clientRolesReadRoles, h.clientOfflineSessionCount))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/offline-sessions",
		h.guardAny(clientRolesReadRoles, h.clientOfflineSessions))
	mux.HandleFunc("POST /admin/realms/{realm}/clients/{clientUUID}/push-revocation",
		h.guard("manage-clients", h.pushClientRevocation))

	// Client scopes. The whole family is authorised out of the **clients**
	// role set, which is the surprise: view-realm and manage-realm are 403 on
	// every route below, including the three the OpenAPI description tags
	// `Realms Admin`. Measured 2026-08-29 one role at a time over eight
	// candidates.
	//
	// Reading takes view-clients or manage-clients and writing takes
	// manage-clients alone, and query-clients is admitted by the coarse gate
	// and answered with an empty body rather than a refusal - the client
	// listing's shape, and maySeeClientScopes is what empties it.
	//
	// `client-templates` is a deprecated path alias for `client-scopes`.
	// Measured on all three verbs: the listing is the same fifteen, the single
	// read is byte-identical, and a DELETE through it removes the scope. Five
	// operations the description counts separately and one handler serves.
	for _, base := range []string{"client-scopes", "client-templates"} {
		mux.HandleFunc("GET /admin/realms/{realm}/"+base,
			h.guardAny(clientsReadRoles, h.listClientScopes))
		mux.HandleFunc("POST /admin/realms/{realm}/"+base,
			h.guard("manage-clients", h.createClientScope))
		mux.HandleFunc("GET /admin/realms/{realm}/"+base+"/{clientScopeID}",
			h.guardClientScope(h.readClientScope))
		mux.HandleFunc("PUT /admin/realms/{realm}/"+base+"/{clientScopeID}",
			h.guardClientScope(h.updateClientScope))
		mux.HandleFunc("DELETE /admin/realms/{realm}/"+base+"/{clientScopeID}",
			h.guardClientScope(h.deleteClientScope))
	}

	// Protocol mappers, twenty-one operations over two containers and three
	// path spellings. Measured 2026-08-30: the `client-templates` alias serves
	// what its `client-scopes` sibling serves byte for byte on all seven,
	// headers included, and `POST` echoes the path it was called on into
	// Location - the same single exception the parent family has.
	//
	// The coarse gate is **two** roles here and three one level up:
	// query-clients reads GET /client-scopes as `200 []` and is 403 on every
	// one of these. See clientScopeMapperReadRoles.
	for _, base := range []string{"client-scopes", "client-templates"} {
		prefix := "/admin/realms/{realm}/" + base + "/{clientScopeID}/protocol-mappers"
		mux.HandleFunc("GET "+prefix+"/models", h.guardScopeMappers(false, h.listProtocolMappers))
		mux.HandleFunc("POST "+prefix+"/models", h.guardScopeMappers(true, h.createProtocolMapper))
		mux.HandleFunc("GET "+prefix+"/models/{mapperID}", h.guardScopeMappers(false, h.readProtocolMapper))
		mux.HandleFunc("PUT "+prefix+"/models/{mapperID}", h.guardScopeMappers(true, h.updateProtocolMapper))
		mux.HandleFunc("DELETE "+prefix+"/models/{mapperID}", h.guardScopeMappers(true, h.deleteProtocolMapper))
		mux.HandleFunc("GET "+prefix+"/protocol/{protocol}", h.guardScopeMappers(false, h.listProtocolMappersByProtocol))
		mux.HandleFunc("POST "+prefix+"/add-models", h.guardScopeMappers(true, h.addProtocolMappers))
	}
	{
		prefix := "/admin/realms/{realm}/clients/{clientUUID}/protocol-mappers"
		mux.HandleFunc("GET "+prefix+"/models", h.guardClientMappers(false, h.listProtocolMappers))
		mux.HandleFunc("POST "+prefix+"/models", h.guardClientMappers(true, h.createProtocolMapper))
		mux.HandleFunc("GET "+prefix+"/models/{mapperID}", h.guardClientMappers(false, h.readProtocolMapper))
		mux.HandleFunc("PUT "+prefix+"/models/{mapperID}", h.guardClientMappers(true, h.updateProtocolMapper))
		mux.HandleFunc("DELETE "+prefix+"/models/{mapperID}", h.guardClientMappers(true, h.deleteProtocolMapper))
		mux.HandleFunc("GET "+prefix+"/protocol/{protocol}", h.guardClientMappers(false, h.listProtocolMappersByProtocol))
		mux.HandleFunc("POST "+prefix+"/add-models", h.guardClientMappers(true, h.addProtocolMappers))
	}

	// Scope mappings, thirty-three operations over two containers and three
	// path spellings. Measured 2026-08-30: `client-templates` serves what
	// `client-scopes` serves byte for byte on all eleven, headers included -
	// **with no exception at all**, where the parent family and the protocol
	// mappers each had one. Both exceptions were `POST` echoing its own path
	// into `Location`, and nothing on this tag mints a `Location`: the two
	// writes are 204 with no body.
	//
	// The gate and the fine check are the protocol-mapper family's, reused
	// after measuring them here. The per-role check inside the handlers is
	// **not** the user family's - see mayMapRole.
	//
	// The `{client}` segment is named roleClientUUID rather than clientUUID so
	// the client-owner family below can carry both: on
	// /clients/{clientUUID}/scope-mappings/clients/{roleClientUUID} the two are
	// different clients, and one name for both would silently resolve the
	// container where the role container was meant.
	for _, base := range []string{"client-scopes", "client-templates"} {
		prefix := "/admin/realms/{realm}/" + base + "/{clientScopeID}/scope-mappings"
		h.registerScopeMappings(mux, prefix, h.guardScopeScopeMappings)
	}
	h.registerScopeMappings(mux,
		"/admin/realms/{realm}/clients/{clientUUID}/scope-mappings",
		h.guardClientScopeMappings)

	// The scope evaluator. Five of the tag's seven; the two that mint a
	// userinfo document and a SAML assertion are Pending, for the boundary
	// reasons evaluatescopes.go records.
	//
	// **Two guards, not one**, and the split was measured rather than assumed.
	// The three reads take the protocol mappers' pair - view-clients or
	// manage-clients, with query-clients admitted by the coarse gate and
	// refused by the fine check. The two generators refuse **every single
	// role** and need a client-read role and a user-read role held together,
	// which is /roles/{name}/users' conjunction shape met a second time.
	{
		prefix := "/admin/realms/{realm}/clients/{clientUUID}/evaluate-scopes"
		mux.HandleFunc("GET "+prefix+"/protocol-mappers",
			h.guardEvaluateScopes(h.listEvaluatedProtocolMappers))
		mux.HandleFunc("GET "+prefix+"/scope-mappings/{roleContainerID}/granted",
			h.guardEvaluateScopes(h.evaluatedScopeMappings(true)))
		mux.HandleFunc("GET "+prefix+"/scope-mappings/{roleContainerID}/not-granted",
			h.guardEvaluateScopes(h.evaluatedScopeMappings(false)))
		mux.HandleFunc("GET "+prefix+"/generate-example-access-token",
			h.guardExampleToken(h.generateExampleAccessToken))
		mux.HandleFunc("GET "+prefix+"/generate-example-id-token",
			h.guardExampleToken(h.generateExampleIDToken))
	}

	// The realm's own two default sets. Tagged `Realms Admin` and guarded like
	// a client: manage-clients writes them and view-realm cannot read them.
	//
	// The resolution order is the **opposite** of the routes above. Here the
	// role check runs first and the scope second - a view-clients caller naming
	// a scope that does not exist gets 403 where the same caller on
	// /client-scopes/{id} gets 404 - which is why these go through guard() with
	// the lookup inside the handler rather than through guardClientScope.
	mux.HandleFunc("GET /admin/realms/{realm}/default-default-client-scopes",
		h.guardAny(clientsReadRoles, h.listRealmDefaultScopes(true)))
	mux.HandleFunc("PUT /admin/realms/{realm}/default-default-client-scopes/{clientScopeID}",
		h.guard("manage-clients", h.addRealmDefaultScope(true)))
	mux.HandleFunc("DELETE /admin/realms/{realm}/default-default-client-scopes/{clientScopeID}",
		h.guard("manage-clients", h.removeRealmDefaultScope))
	mux.HandleFunc("GET /admin/realms/{realm}/default-optional-client-scopes",
		h.guardAny(clientsReadRoles, h.listRealmDefaultScopes(false)))
	mux.HandleFunc("PUT /admin/realms/{realm}/default-optional-client-scopes/{clientScopeID}",
		h.guard("manage-clients", h.addRealmDefaultScope(false)))
	mux.HandleFunc("DELETE /admin/realms/{realm}/default-optional-client-scopes/{clientScopeID}",
		h.guard("manage-clients", h.removeRealmDefaultScope))

	// A client's own two sets, tagged `Clients` and built here because the
	// resource is a client scope. A third resolution order again: the client
	// first, the manage-clients check second, the scope third - measured, a
	// view-clients caller gets 404 for an unknown client and 403 for a known
	// client with an unknown scope.
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/default-client-scopes",
		h.guardAny(clientsReadRoles, h.listClientClientScopes(true)))
	mux.HandleFunc("PUT /admin/realms/{realm}/clients/{clientUUID}/default-client-scopes/{clientScopeID}",
		h.guardAny(clientsReadRoles, h.addClientClientScope(true)))
	mux.HandleFunc("DELETE /admin/realms/{realm}/clients/{clientUUID}/default-client-scopes/{clientScopeID}",
		h.guardAny(clientsReadRoles, h.removeClientClientScope))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/optional-client-scopes",
		h.guardAny(clientsReadRoles, h.listClientClientScopes(false)))
	mux.HandleFunc("PUT /admin/realms/{realm}/clients/{clientUUID}/optional-client-scopes/{clientScopeID}",
		h.guardAny(clientsReadRoles, h.addClientClientScope(false)))
	mux.HandleFunc("DELETE /admin/realms/{realm}/clients/{clientUUID}/optional-client-scopes/{clientScopeID}",
		h.guardAny(clientsReadRoles, h.removeClientClientScope))

	// Realm roles: reading admits view-realm or manage-realm and writing needs
	// manage-realm - measured across eight single-role callers, none of the
	// users or clients roles opens any of them. manage-realm reading too is
	// not a composite - it is its own role with no children - so it has to be
	// admitted here rather than reached through view-realm.
	mux.HandleFunc("GET /admin/realms/{realm}/roles", h.guardAny(realmRolesReadRoles, h.listRealmRoles))
	mux.HandleFunc("GET /admin/realms/{realm}/roles/{roleName}", h.guardAny(realmRolesReadRoles, h.readRealmRole))
	mux.HandleFunc("POST /admin/realms/{realm}/roles", h.guard("manage-realm", h.createRealmRole))
	mux.HandleFunc("PUT /admin/realms/{realm}/roles/{roleName}", h.guard("manage-realm", h.updateRealmRole))
	mux.HandleFunc("DELETE /admin/realms/{realm}/roles/{roleName}", h.guard("manage-realm", h.deleteRealmRole))

	// Client roles: the same split as the realm roles above - reading admits
	// view-clients or manage-clients, and writing needs manage-clients alone.
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles", h.guardAny(clientRolesReadRoles, h.listClientRoles))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}", h.guardAny(clientRolesReadRoles, h.readClientRole))
	mux.HandleFunc("POST /admin/realms/{realm}/clients/{clientUUID}/roles", h.guard("manage-clients", h.createClientRole))
	mux.HandleFunc("PUT /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}", h.guard("manage-clients", h.updateClientRole))
	mux.HandleFunc("DELETE /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}", h.guard("manage-clients", h.deleteClientRole))

	// Composites, for both realm roles and client roles. The five shapes are
	// the same either side; only the locator differs. Reads take the same
	// guardAny pair as the plain role reads next door - measured directly
	// rather than assumed from that sibling, since two earlier tasks had to
	// correct exactly this assumption: a caller holding only view-realm and
	// one holding only manage-realm both get 200 on GET .../composites, and
	// the client side mirrors it with view-clients/manage-clients. Writes
	// (POST and DELETE) admit only the manage role on either side - measured
	// the same way, with the view role and the other side's manage role both
	// 403.
	mux.HandleFunc("GET /admin/realms/{realm}/roles/{roleName}/composites",
		h.guardAny(realmRolesReadRoles, h.listComposites(h.realmRole, nil)))
	mux.HandleFunc("GET /admin/realms/{realm}/roles/{roleName}/composites/realm",
		h.guardAny(realmRolesReadRoles, h.listComposites(h.realmRole, onlyRealmRoles)))
	mux.HandleFunc("GET /admin/realms/{realm}/roles/{roleName}/composites/clients/{targetClientUUID}",
		h.guardAny(realmRolesReadRoles, h.listComposites(h.realmRole, onlyThisClientsRoles)))
	mux.HandleFunc("POST /admin/realms/{realm}/roles/{roleName}/composites",
		h.guard("manage-realm", h.addComposites(h.realmRole)))
	mux.HandleFunc("DELETE /admin/realms/{realm}/roles/{roleName}/composites",
		h.guard("manage-realm", h.removeComposites(h.realmRole)))

	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/composites",
		h.guardAny(clientRolesReadRoles, h.listComposites(h.clientRoleLocator, nil)))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/composites/realm",
		h.guardAny(clientRolesReadRoles, h.listComposites(h.clientRoleLocator, onlyRealmRoles)))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/composites/clients/{targetClientUUID}",
		h.guardAny(clientRolesReadRoles, h.listComposites(h.clientRoleLocator, onlyThisClientsRoles)))
	mux.HandleFunc("POST /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/composites",
		h.guard("manage-clients", h.addComposites(h.clientRoleLocator)))
	mux.HandleFunc("DELETE /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/composites",
		h.guard("manage-clients", h.removeComposites(h.clientRoleLocator)))

	// The holders of a role. .../groups takes the same view/manage pair as the
	// plain role reads and the composites above it - measured the same way, not
	// assumed from that sibling.
	//
	// .../users does not: measured against a live 26.7.1 with every single
	// master-realm role tried alone and in combination, it 403s a caller
	// holding only view-realm/manage-realm/view-clients/manage-clients *and*
	// one holding only view-users/manage-users/query-users, and 200s only a
	// caller holding one of each pair together. That is a conjunction of two
	// role families neither guard nor guardAny expresses, so it gets its own
	// combinator rather than a third slice bolted onto guardAny's contract.
	mux.HandleFunc("GET /admin/realms/{realm}/roles/{roleName}/users",
		h.guardAnyAndAny(realmRolesReadRoles, usersReadRoles, h.roleUsers(h.realmRole)))
	mux.HandleFunc("GET /admin/realms/{realm}/roles/{roleName}/groups",
		h.guardAny(realmRolesReadRoles, h.roleGroups(h.realmRole)))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/users",
		h.guardAnyAndAny(clientRolesReadRoles, usersReadRoles, h.roleUsers(h.clientRoleLocator)))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/groups",
		h.guardAny(clientRolesReadRoles, h.roleGroups(h.clientRoleLocator)))

	// roles-by-id: the same eight operations, addressed by the role's own id
	// rather than by name/container path. The required role is decided by the
	// role's own container once it is resolved, not by the route - measured
	// against a live 26.7.1 for both a realm role and a client role id, across
	// every plain master-realm role. Reads take the same view/manage pair as
	// the by-name reads next door (a single measurement of view-realm and
	// view-clients alone had this wrong as a single role; manage-realm and
	// manage-clients were checked too and both open it). Writes - PUT, DELETE
	// and POST/DELETE .../composites - take only the manage role on the
	// resolved role's own side, measured the same way. See
	// guardByRoleContainer and the "roles-by-id" section of
	// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
	mux.HandleFunc("GET /admin/realms/{realm}/roles-by-id/{roleID}",
		h.guardByRoleContainer(realmRolesReadRoles, clientRolesReadRoles, h.readRoleByID))
	mux.HandleFunc("PUT /admin/realms/{realm}/roles-by-id/{roleID}",
		h.guardByRoleContainer([]string{"manage-realm"}, []string{"manage-clients"}, h.updateRoleByID))
	mux.HandleFunc("DELETE /admin/realms/{realm}/roles-by-id/{roleID}",
		h.guardByRoleContainer([]string{"manage-realm"}, []string{"manage-clients"}, h.deleteRoleByID))
	mux.HandleFunc("GET /admin/realms/{realm}/roles-by-id/{roleID}/composites",
		h.guardByRoleContainer(realmRolesReadRoles, clientRolesReadRoles, h.compositesByID(nil)))
	mux.HandleFunc("GET /admin/realms/{realm}/roles-by-id/{roleID}/composites/realm",
		h.guardByRoleContainer(realmRolesReadRoles, clientRolesReadRoles, h.compositesByID(onlyRealmRoles)))
	mux.HandleFunc("GET /admin/realms/{realm}/roles-by-id/{roleID}/composites/clients/{targetClientUUID}",
		h.guardByRoleContainer(realmRolesReadRoles, clientRolesReadRoles, h.compositesByID(onlyThisClientsRoles)))
	mux.HandleFunc("POST /admin/realms/{realm}/roles-by-id/{roleID}/composites",
		h.guardByRoleContainer([]string{"manage-realm"}, []string{"manage-clients"}, h.addCompositesByID))
	mux.HandleFunc("DELETE /admin/realms/{realm}/roles-by-id/{roleID}/composites",
		h.guardByRoleContainer([]string{"manage-realm"}, []string{"manage-clients"}, h.removeCompositesByID))
}

// registerScopeMappings declares one container's eleven scope-mapping routes.
//
// A function rather than a third copy of the eleven lines, because the three
// families are measured byte-identical and the only thing that differs is the
// guard - which is exactly what a divergence between two copies would hide.
// The two protocol-mapper loops next door are seven lines each and were written
// out; eleven times three is where that stops being the smaller diff.
func (h *handler) registerScopeMappings(mux *http.ServeMux, prefix string,
	guard func(bool, func(http.ResponseWriter, *http.Request, *reqContext, scopeContainer)) http.HandlerFunc) {
	mux.HandleFunc("GET "+prefix, guard(false, h.allScopeMappings))
	mux.HandleFunc("GET "+prefix+"/realm", guard(false, h.listRealmScopeMappings))
	mux.HandleFunc("GET "+prefix+"/realm/available", guard(false, h.availableRealmScopeMappings))
	mux.HandleFunc("GET "+prefix+"/realm/composite", guard(false, h.compositeRealmScopeMappings))
	mux.HandleFunc("POST "+prefix+"/realm", guard(true, h.addRealmScopeMappings))
	mux.HandleFunc("DELETE "+prefix+"/realm", guard(true, h.removeRealmScopeMappings))
	mux.HandleFunc("GET "+prefix+"/clients/{roleClientUUID}", guard(false, h.listClientRoleScopeMappings))
	mux.HandleFunc("GET "+prefix+"/clients/{roleClientUUID}/available", guard(false, h.availableClientRoleScopeMappings))
	mux.HandleFunc("GET "+prefix+"/clients/{roleClientUUID}/composite", guard(false, h.compositeClientRoleScopeMappings))
	mux.HandleFunc("POST "+prefix+"/clients/{roleClientUUID}", guard(true, h.addClientRoleScopeMappings))
	mux.HandleFunc("DELETE "+prefix+"/clients/{roleClientUUID}", guard(true, h.removeClientRoleScopeMappings))
}

// guard is the authorization filter every admin route goes through: resolve
// the realm, resolve the caller from its session, then check the one role this
// operation requires.
//
// The role is per operation rather than a blanket "is an admin" check, because
// that is what was measured: a caller holding view-users and nothing else gets
// 200 listing users and 403 creating one.
func (h *handler) guard(role string, next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return h.guardRejecting(role, writeForbidden, next)
}

// guardAny is guard for a route that more than one role opens. The user
// listing and count take view-users, query-users or manage-users; reading one
// user takes only the first and third.
func (h *handler) guardAny(roles []string, next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return h.guardAnyRejecting(roles, writeForbidden, next)
}

// guardRejecting is guard with the rejection spelled out, for the one route
// that does not answer 403.
//
// DELETE .../client-secret/rotated answers 500 to a caller lacking its role -
// Keycloak's own error handler raises a NullPointerException while formatting
// the ForbiddenException. Measured, reproducible, and copied on purpose. A
// route with a different rejection has to say so at the call site rather than
// hiding it in the handler, because the rejection happens before the handler
// runs.
func (h *handler) guardRejecting(role string, reject func(http.ResponseWriter), next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return h.guardAnyRejecting([]string{role}, reject, next)
}

// guardAnyAndAny is guard for the one route in this file that needs a role
// from each of two families rather than any of one: .../roles/{name}/users
// needs a role-management role (a: realmRolesReadRoles or
// clientRolesReadRoles) together with a user-read role (b: usersReadRoles) -
// measured, not assumed from guardAny's single-family siblings. It is built
// from guardAnyRejecting rather than duplicated: that call resolves the
// realm and the caller and checks the first family, and the wrapped next
// adds the second check before running the handler.
func (h *handler) guardAnyAndAny(a, b []string, next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return h.guardAnyRejecting(a, writeForbidden, func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		if !rc.caller.hasAny(b) {
			writeForbidden(w)
			return
		}
		next(w, r, rc)
	})
}

// guardUserSubject is the two-stage guard every route naming a {userID} takes:
// a coarse check, then the subject, then the route's own roles.
//
// Keycloak checks twice with the subject resolved in between, so a caller that
// passes the coarse gate learns whether the user exists even when the route is
// closed to it, and a caller that fails the coarse gate does not. Measured
// 2026-08-28 across all 18 routes in the family - the single-user reads and
// writes, the whole credential family, the logout, and the seven role-mapping
// routes - on a user id that resolves to nothing, one caller per role and a
// fresh token minted immediately before every call. Every one of them answers
// 404 "User not found" to view-users, query-users and manage-users alike, and
// 403 to every role outside those three.
//
// **The coarse gate is usersReadRoles and it is wider than any route's own
// roles**, which is the whole point: query-users opens no route in the family -
// not one - and still gets the 404 everywhere. A single-stage guard cannot
// express that, which is why this exists rather than another guardAny.
//
// fine is what the route itself takes, checked after the subject. The order is
// what makes 404 reachable for a caller the route refuses.
func (h *handler) guardUserSubject(fine []string, next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return h.guardUserSubjectResolving(func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		if !rc.caller.hasAny(fine) {
			writeForbidden(w)
			return
		}
		next(w, r, rc)
	})
}

// guardUserSubjectResolving is the first two stages on their own: the coarse
// gate and the subject. What follows differs between the plain routes, which
// check the role next, and the client mapping routes, which resolve a client
// first.
func (h *handler) guardUserSubjectResolving(next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return h.guardAnyRejecting(usersReadRoles, writeForbidden, func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		user, ok := h.userFromPath(w, r, rc)
		if !ok {
			return
		}
		rc.subject = user
		next(w, r, rc)
	})
}

// guardGroup is guard for the routes that name a {groupID}: the group is
// resolved **before the caller is judged at all**.
//
// Measured 2026-08-28 across all six of them, seven callers each: a group that
// does not exist answers 404 "Could not find group by id" to every caller,
// including one holding no admin role. The roles only reappear once the group
// is real. So the order is realm, authentication, group, authorization.
//
// **This is not guardUserSubject's shape and the difference is the point.** On
// /users/{id}/... a coarse gate runs first, so a caller outside the users
// family gets 403 and learns nothing about the subject. Here there is no coarse
// gate. query-groups opening the group listing and count and nothing else made
// the users-family shape look like the obvious fit, and it is wrong; only the
// missing-group sweep says so. guardByRoleContainer records the same
// resolve-first behaviour for /roles-by-id/{id}, and notes there too that it is
// Keycloak's behaviour rather than a safe one.
func (h *handler) guardGroup(fine []string, next func(http.ResponseWriter, *http.Request, *reqContext, *model.Group)) http.HandlerFunc {
	return h.guardGroupResolving(func(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
		if !rc.caller.hasAny(fine) {
			writeForbidden(w)
			return
		}
		next(w, r, rc, g)
	})
}

// guardClientScope is the realm, the caller, the coarse clients gate, then the
// client scope - and the fine per-verb role check is left to the handler,
// because it runs **after** the lookup.
//
// That ordering is measured rather than chosen. A view-clients caller naming a
// scope that does not exist is answered 404 by GET, PUT and DELETE alike; the
// same caller naming a scope that does exist is answered 200 by GET and 403 by
// the two writes. So the 404 precedes the 403 here, the way it does on
// /roles-by-id/{id} and the way it does not on the realm's default-scope
// routes next door.
//
// A caller holding none of the three clients roles never gets that far: the
// coarse gate answers 403 even for a scope that does not exist, so the leak is
// to a client-reading caller only. create-client is not in the gate and is 403
// on everything.
func (h *handler) guardClientScope(next func(http.ResponseWriter, *http.Request, *reqContext, *model.ClientScope)) http.HandlerFunc {
	return h.guardAnyRejecting(clientsReadRoles, writeForbidden,
		func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
			sc, err := h.store.ClientScopes().ByID(r.Context(), rc.realm.ID,
				r.PathValue("clientScopeID"))
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					writeClientScopeNotFound(w)
					return
				}
				httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			next(w, r, rc, sc)
		})
}

// guardGroupResolving is the realm, the caller and the group, with no role
// check. What follows differs between the plain group routes and the six that
// name a client, which resolve it before judging the caller.
func (h *handler) guardGroupResolving(next func(http.ResponseWriter, *http.Request, *reqContext, *model.Group)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		group, err := h.store.Groups().ByID(r.Context(), realm.ID, r.PathValue("groupID"))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeGroupNotFound(w)
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		next(w, r, &reqContext{realm: realm, caller: c}, group)
	}
}

// guardGroupClient is guardGroup for the six group routes that name a client
// as well: the client is resolved **after the group and before the role check**.
//
// Measured 2026-08-28: a real group with an unknown client answers 404
// "Client not found" to every caller, including one holding no admin role, and
// an unknown group with an unknown client answers about the **group**. So the
// order is group, client, roles.
func (h *handler) guardGroupClient(fine []string, next func(http.ResponseWriter, *http.Request, *reqContext, *model.Group)) http.HandlerFunc {
	return h.guardGroupResolving(func(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
		if _, ok := h.mappingClientFromPath(w, r, rc); !ok {
			return
		}
		if !rc.caller.hasAny(fine) {
			writeForbidden(w)
			return
		}
		next(w, r, rc, g)
	})
}

// guardUserSubjectClient is guardUserSubject for the six user mapping routes
// that name a client: the client is resolved after the subject and **before the
// route's own role check**.
//
// Measured 2026-08-28, and Gloak diverged here before cut C found it. A real
// user with an unknown client answers 404 "Client not found" to every caller,
// including one that fails the coarse gate - where an unknown user **and** an
// unknown client answers 403 to that same caller. So the client's 404 does not
// depend on the gate and the user's does, which is why this cannot be expressed
// by moving one check.
func (h *handler) guardUserSubjectClient(fine []string, next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		rc := &reqContext{realm: realm, caller: c}

		// **The subject's absence is gated and the client's is not**, which is
		// why this is written out rather than layered on guardUserSubject.
		// Measured on a caller with no admin role: a real user with an unknown
		// client answers 404 "Client not found", an unknown user with a real
		// client answers 403, and an unknown user with an unknown client
		// answers 403 - so the user is resolved first and the coarse gate
		// decides only when it is missing.
		user, err := h.store.Users().ByID(r.Context(), realm.ID, r.PathValue("userID"))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				if !c.hasAny(usersReadRoles) {
					writeForbidden(w)
					return
				}
				writeUserNotFound(w)
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		rc.subject = user

		if _, ok := h.mappingClientFromPath(w, r, rc); !ok {
			return
		}
		if !c.hasAny(fine) {
			writeForbidden(w)
			return
		}
		next(w, r, rc)
	}
}

// guardByRoleContainer is guard for the roles-by-id routes, whose required
// role is decided by the **data** rather than by the route: the role has to
// be resolved before the caller can be judged, because the same path takes
// realmRoles for a realm role and clientRoles for a client role. Both take a
// slice rather than a single role, mirroring guardAny's contract - measured
// directly rather than assumed from the by-name reads next door: a single
// earlier measurement of view-realm and view-clients alone made this look
// like a lone role, and manage-realm/manage-clients opening it too was found
// on the second pass.
//
// The order matters and is measured too: the role is resolved first, so a
// missing role answers 404 whatever the caller holds. That is Keycloak's own
// behaviour, not a defensive choice - and it is not a safe one. Answering the
// existence question before the authorization question means an
// unauthorized caller can tell a missing id (404) apart from one that exists
// but it may not touch (403), which is exactly the ordering an access-control
// design would normally avoid. It is kept here because it is what was
// measured, not because it is the safer order.
func (h *handler) guardByRoleContainer(realmRoles, clientRoles []string, next func(http.ResponseWriter, *http.Request, *reqContext, *model.Role)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		role, err := h.store.Roles().ByID(r.Context(), realm.ID, r.PathValue("roleID"))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeRoleIDNotFound(w)
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		required := realmRoles
		if role.ClientID != "" {
			required = clientRoles
		}
		if !c.hasAny(required) {
			writeForbidden(w)
			return
		}
		next(w, r, &reqContext{realm: realm, caller: c}, role)
	}
}

// guardRealms is the guard for the two routes with no {realm} segment.
//
// Every other combinator in this file starts with resolveRealm, which reads
// r.PathValue("realm"); there is none here, so the caller is authenticated in
// the realm its token names and the handler decides the rest. The listing
// filters per realm and the create takes one role, and neither question can be
// asked before the caller is known.
func (h *handler) guardRealms(next func(http.ResponseWriter, *http.Request, *caller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := h.resolveCaller(w, r, nil)
		if c == nil {
			return
		}
		next(w, r, c)
	}
}

// guardRealmsWithRole is guardRealms plus one role, for POST /admin/realms.
// create-realm is a **realm** role in master, so it reaches adminGrants by name
// rather than through a container - see adminRoleNames - and a caller outside
// master holds no such role at all.
func (h *handler) guardRealmsWithRole(role string, next func(http.ResponseWriter, *http.Request, *caller)) http.HandlerFunc {
	return h.guardRealms(func(w http.ResponseWriter, r *http.Request, c *caller) {
		if !c.has(role) {
			writeForbidden(w)
			return
		}
		next(w, r, c)
	})
}

// guardRealmRead is GET /admin/realms/{realm}'s guard, and it is the only one
// whose admission is not a role list.
//
// A caller in master holding **any** admin role on **any** container reads
// every realm, at the reduced level if it holds no view-realm there - measured
// on a caller holding only the realm role create-realm, which owns no container
// at all. impersonation is the one admin role that opens nothing. See
// maySeeRealm.
func (h *handler) guardRealmRead(next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		ok, err := h.maySeeRealm(r.Context(), c, realm.Name)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if !ok {
			writeForbidden(w)
			return
		}
		next(w, r, &reqContext{realm: realm, caller: c})
	}
}

// guardRealmContainerAny admits any admin role of the realm's **own**
// container except impersonation, and nothing else.
//
// It is the realm listing's per-row question - containerRoleNames plus
// opensARealm - asked as a route guard, and it is measured rather than
// borrowed. Swept 2026-09-03 on GET .../localization and
// GET .../localization/{locale}/{key} over all 21 roles of the target realm's
// container, a caller holding only the realm role create-realm, and one holding
// nothing:
//
//	every container role but impersonation   200
//	impersonation                            403
//	create-realm                             403
//	nothing                                  403
//	a role on **another** realm's container   403
//
// The two roles that separate it from guardRealmRead are the last two rows.
// guardRealmRead admits a create-realm holder and reaches sideways into other
// realms; this does neither, and the third read in the same family takes that
// other guard. One family, two admissions, one path segment apart.
func (h *handler) guardRealmContainerAny(next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		if !opensARealm(containerRoleNames(c.container, c.effective)) {
			writeForbidden(w)
			return
		}
		next(w, r, &reqContext{realm: realm, caller: c})
	}
}

// guardGroupPath is guardGroup for the one route that names a group by its
// path rather than its id: the path is resolved **before the caller is judged**.
//
// Measured 2026-08-29 on three callers - one holding nothing, one holding
// create-client and one holding view-users - all three of which answer 404
// "Group path does not exist" for a path that resolves to nothing, while a
// path that resolves answers 403 to the first two. That is guardGroup's
// ordering on a route the description tags Realms Admin rather than Groups, so
// it is measured here rather than inherited from either neighbour.
func (h *handler) guardGroupPath(fine []string, next func(http.ResponseWriter, *http.Request, *reqContext, *model.Group)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		group, err := h.groupAtPath(r, realm.ID, groupByPathSegments(r.PathValue("path")))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeGroupPathNotFound(w)
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		rc := &reqContext{realm: realm, caller: c}
		if !c.hasAny(fine) {
			writeForbidden(w)
			return
		}
		next(w, r, rc, group)
	}
}

// guardRealmFeature is the guard for a route whose whole answer is "that
// feature is off": authenticate, resolve the realm, and hand over.
//
// **The order it expresses is measured and it is nobody else's.** On
// /admin/realms/{realm}/client-types, no token is 401, an unknown realm with a
// valid token is 404 "Realm not found.", and then *every* authenticated caller
// gets the 501 - including one holding no admin role at all. So the feature
// check sits between the realm and the authorization check, which means there
// is no role list to write down and guardAny with an empty slice would refuse
// everybody instead.
func (h *handler) guardRealmFeature(next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		next(w, r, &reqContext{realm: realm, caller: c})
	}
}

// writeFeatureNotEnabled is what both client-types operations answer on a
// default 26.7.1: CLIENT_TYPES is a disabled preview feature, so 501 is the
// endpoint's contract and not a stub. The wording is the generic one Keycloak
// uses when it cannot say more - the same description the realm PUT's 500
// carries - and it is a 501 rather than a 404 or a 403.
func writeFeatureNotEnabled(w http.ResponseWriter, _ *http.Request, _ *reqContext) {
	httpx.WriteOAuthError(w, http.StatusNotImplemented, "Feature not enabled",
		"For more on this error consult the server log.")
}

// guardOrganizations is the guard every route under /organizations takes:
// authenticate, resolve the realm, check the roles, **then** check the realm's
// organizationsEnabled flag.
//
// **The order is the opposite of guardRealmFeature's, and that is measured
// rather than assumed from the resemblance.** On
// GET /admin/realms/master/organizations with the flag off:
//
//	no Authorization header      401 {"error":"HTTP 401 Unauthorized"}
//	unknown realm                404 {"error":"Realm not found."}
//	a caller holding no role     403 {"error":"HTTP 403 Forbidden"}
//	view-organizations           404 Organizations not enabled for this realm.
//	a full administrator         404 Organizations not enabled for this realm.
//
// client-types puts its feature check **before** the authorization check and
// therefore has no role list at all; this one puts it after and therefore has
// one. Reusing guardRealmFeature here would answer 404 where Keycloak answers
// 403, which is the whole difference between the two families.
func (h *handler) guardOrganizations(roles []string, next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return h.guardAny(roles, func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		if !organizationsEnabled(rc.realm) {
			writeOrganizationsNotEnabled(w)
			return
		}
		next(w, r, rc)
	})
}

// guardOrganization is guardOrganizations for the three routes naming an
// {orgID}: the organization is resolved **after** the caller is judged.
//
// Measured 2026-08-31 on an id that resolves to nothing: a caller holding no
// admin role gets 403 and one holding view-organizations gets 404. That is the
// users family's shape and **not** the groups family's, where every route
// naming a {groupID} answers 404 to every caller including one holding
// nothing. The description tags both families' routes after their own
// resource, so the tag does not predict it here either.
func (h *handler) guardOrganization(roles []string, next func(http.ResponseWriter, *http.Request, *reqContext, *model.Organization)) http.HandlerFunc {
	return h.guardOrganizations(roles, func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		org, ok := h.organizationFromPath(w, r, rc)
		if !ok {
			return
		}
		next(w, r, rc, org)
	})
}

// organizationFromPath resolves the {orgID} segment, or writes the 404. It is
// shared by the two guards above so that the twenty-one routes naming an
// organization cannot come to answer a missing one differently.
func (h *handler) organizationFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.Organization, bool) {
	org, err := h.store.Organizations().ByID(r.Context(), rc.realm.ID, r.PathValue("orgID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeOrganizationNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return org, true
}

// guardOrganizationsAnd is guardOrganizations for a route that needs a role
// from each of two families rather than any of one. It is separate from
// guardOrganizationAnd below because the family has a route with no {orgID} in
// its path, which is measured and unserved for a routing reason.
//
// **Nineteen routes need one and none of them is opened by a single role.**
// Measured 2026-09-02: `manage-organizations` alone is 403 on every member
// route and so is `manage-users` alone; `view-organizations` together with
// `view-users` is 200. That is guardAnyAndAny's shape - `/roles/{name}/users`
// is the only other place in this API with it - with the realm flag checked in
// between, which is why it is built here rather than there.
func (h *handler) guardOrganizationsAnd(a, b []string, next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return h.guardOrganizations(a, func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		if !rc.caller.hasAny(b) {
			writeForbidden(w)
			return
		}
		next(w, r, rc)
	})
}

// guardOrganizationAnd is guardOrganizationsAnd with the {orgID} resolved, for
// the eighteen routes that name one. The organization comes **after** both role
// checks, which is guardOrganization's measured order and holds here too: an
// org id that resolves to nothing answers 403 to a caller holding nothing and
// `404 {"errorMessage":"Organization not found."}` to a full administrator, on
// every one of the eighteen.
func (h *handler) guardOrganizationAnd(a, b []string, next func(http.ResponseWriter, *http.Request, *reqContext, *model.Organization)) http.HandlerFunc {
	return h.guardOrganizationsAnd(a, b, func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		org, ok := h.organizationFromPath(w, r, rc)
		if !ok {
			return
		}
		next(w, r, rc, org)
	})
}

// guardOrganizationGroupOf resolves the organization and then the group for
// every route naming a {groupID}, and checks the route's own role set **after**
// both.
//
// **That order is measured, and it is not guardOrganization's.** With one token
// per role on 2026-09-03:
//
//	view-users, on any route, any id            403
//	view-organizations, unknown organization    404 Organization not found.
//	view-organizations, DELETE an unknown group 404 Group does not exist
//	view-organizations, PUT an existing group   403
//
// So the tag's **read** pair gates first, the organization and the group are
// resolved next, and the write pair is judged last. A guard that checked the
// write role first - which is what the member family's does - would answer 403
// where Keycloak answers 404 on every write in this family.
//
// It is also the **opposite shape** from the member family in the other sense:
// `manage-organizations` alone opens nineteen of these twenty-two routes and
// was 403 on all nineteen member routes. Nineteen conjunctions and nineteen
// single-role routes in one tag, measured separately rather than carried over.
func (h *handler) guardOrganizationGroupOf(roles []string,
	next func(http.ResponseWriter, *http.Request, *reqContext, *model.Organization, *model.Group)) http.HandlerFunc {
	return h.guardOrganization(organizationReadRoles, func(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
		// **JAX-RS prefers the group-by-path locator where Go's ServeMux
		// prefers the literal.** `GET .../groups/group-by-path/children`
		// answers the group named `children` on a live 26.7.1 - measured with
		// such a group in the organization - and Go routes it to the children
		// listing instead, because `children` is a literal segment and
		// `group-by-path` is only a wildcard's value. Three route names can
		// collide this way and this is the one place that sees all three.
		if r.Method == http.MethodGet && r.PathValue("groupID") == organizationGroupByPathSegment {
			h.readOrganizationGroupByPath(w, r, rc, o)
			return
		}
		g, ok := h.organizationGroupFromPath(w, r, rc, o)
		if !ok {
			return
		}
		if !rc.caller.hasAny(roles) {
			writeForbidden(w)
			return
		}
		next(w, r, rc, o, g)
	})
}

// guardOrganizationGroup is guardOrganizationGroupOf for the eleven
// role-mapping routes, whose handlers are groupmappings.go's and take a
// *model.Group without the organization.
func (h *handler) guardOrganizationGroup(roles []string,
	next func(http.ResponseWriter, *http.Request, *reqContext, *model.Group)) http.HandlerFunc {
	return h.guardOrganizationGroupOf(roles, func(w http.ResponseWriter, r *http.Request, rc *reqContext, _ *model.Organization, g *model.Group) {
		next(w, r, rc, g)
	})
}

// guardIdentityProvider is guardAny for the five routes naming an {alias}: the
// provider is resolved **after** the caller is judged.
//
// Measured 2026-09-01 on an alias that resolves to nothing: a caller holding no
// admin role gets 403, one holding view-identity-providers gets 404 on the
// reads and 403 on the delete, and one holding manage-identity-providers gets
// 404 on both. So the role check comes first and the route's own role set is
// what decides which of the two answers a caller sees - the
// `default-*-client-scopes` order, and not the Groups tag's, where every route
// naming a resource answers 404 to every caller.
//
// **PUT is deliberately not built on this**, because its decode runs before the
// alias is resolved. See the router entry for it.
func (h *handler) guardIdentityProvider(roles []string, next func(http.ResponseWriter, *http.Request, *reqContext, *model.IdentityProvider)) http.HandlerFunc {
	return h.guardAny(roles, func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		p, err := h.store.IdentityProviders().ByAlias(r.Context(), rc.realm.ID, r.PathValue("alias"))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeIdentityProviderNotFound(w)
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		next(w, r, rc, p)
	})
}

// guardAnyRejecting is the one implementation the three wrappers share:
// resolve the realm, resolve the caller, admit it if it holds any of the
// roles.
func (h *handler) guardAnyRejecting(roles []string, reject func(http.ResponseWriter), next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		if !c.hasAny(roles) {
			reject(w)
			return
		}
		next(w, r, &reqContext{realm: realm, caller: c})
	}
}

// reqContext is what a handler needs that the request itself does not carry:
// the resolved realm and the authenticated caller.
type reqContext struct {
	realm  *model.Realm
	caller *caller
	// subject is the user named by {userID}, resolved by guardUserSubject
	// before the route's own role check runs. userFromPath hands it back
	// rather than looking it up a second time.
	subject *model.User
}

// realmIssuer is the iss claim a token from this realm carries, and therefore
// the value ParseAccess checks against.
func (h *handler) realmIssuer(realm string) string {
	return h.issuerBase + "/realms/" + realm
}

// usersReadRoles is what the user listing and the count accept, and it is also
// the **coarse gate** guardUserSubject applies to every route naming a
// {userID}. Reading one user by ID is not opened by all three: query-users was
// measured getting 403 there and 200 on the other two - but it still gets the
// 404 for a subject that does not exist, which is the distinction the two
// stages exist to draw.
var usersReadRoles = []string{"view-users", "query-users", "manage-users"}

// userReadRoles is what reading one user, and its credential list, accept.
// Measured 2026-08-28 on both: 200 for view-users and manage-users, 403 for
// query-users and for every role outside the family.
//
// **manage-users is on this list and used not to be.** It has no composites at
// all - it is not composite over view-users - so a name-by-name reading of the
// admin roles predicts a caller that may delete a user it may not read. Keycloak
// does not do that, measured on the whole family in one pass; F36 filed the
// suspicion and the sweep confirmed it.
var userReadRoles = []string{"view-users", "manage-users"}

// userWriteRoles is what everything that changes a user takes: the update, the
// delete, the whole credential family and the logout. manage-users alone,
// measured across the same nine callers on all nine routes.
//
// A slice of one, like userMappingsWriteRoles below, because guardUserSubject
// takes the fine stage as a set and a route that names one role should not have
// to say so differently from a route that names two.
var userWriteRoles = []string{"manage-users"}

// userMappingsReadRoles is what the seven role-mapping reads accept - the three
// realm ones, the three client ones and the combined view, swept separately and
// agreeing. Six until the combined view joined them.
// It is usersReadRoles minus query-users, and the two lists are kept separate
// because they were measured separately and disagree: the same caller that
// gets 200 on GET /users gets 403 on GET /users/{id}/role-mappings/realm.
var userMappingsReadRoles = []string{"view-users", "manage-users"}

// userMappingsWriteRole is what all four role-mapping writes take, and it is a
// single role rather than a slice: view-users opens every read above and
// neither verb of either write.
//
// It is named because the two available reads need it too. Their own guard is
// the looser pair above, and the list they answer is measurably the set the
// caller could POST - a view-users caller gets 200 and `[]` - so grantable
// re-applies this before judging any individual role. Spelling it once is what
// stops that filter and this guard from drifting apart.
const userMappingsWriteRole = "manage-users"

// userMappingsWriteRoles is the same role as a set, which is the shape
// guardUserSubject's fine stage takes. The constant above stays because
// grantable asks the question of one role rather than of a route.
var userMappingsWriteRoles = []string{userMappingsWriteRole}

// clientsReadRoles is what the client listing accepts. Measured 2026-08-28 on
// one caller per role: view-clients and manage-clients get 200 and all six,
// query-clients gets 200 and `[]`, everything else 403.
//
// It is the clients-family mirror of usersReadRoles, and the route took
// view-clients alone until that sweep - refusing query-clients, which Keycloak
// admits and empties, and refusing manage-clients, which Keycloak serves in
// full. Wrong in both directions on one route, which is what comes of deriving
// a guard from a role's name: manage-clients is not composite over
// view-clients, so nothing in the role graph predicts it opens a read.
var clientsReadRoles = []string{"view-clients", "query-clients", "manage-clients"}

// authzReadRoles and authzWriteRoles are the authorization services family's,
// swept 2026-08-31 one single role at a time over seven callers - none,
// view-authorization, manage-authorization, view-clients, query-clients,
// manage-clients and manage-realm - on four routes and both verbs.
//
// Three cells surprise, and none of them follows from a role's name:
//
//   - **query-clients is 403 on every one of them**, although it is in
//     clientsReadRoles and although it is admitted by the *client lookup* on
//     these very paths - the caller who may learn a client does not exist may
//     not read its resource server. So the coarse clients gate is not reusable
//     here even though the path starts `/clients/{uuid}`.
//   - **manage-realm is 403 on every one of them**, so this family is not
//     authorised out of the realm set the way the neighbouring client-policy
//     routes are.
//   - **manage-clients is in both sets and view-clients in only the read one**,
//     so the clients family and the authorization family both open this
//     surface and they do it with different halves of themselves.
//
// The two sets differ by exactly the two view roles, which looks like a read
// set and a write set and is measurably not: GET .../settings takes the *write*
// set. See the router entry for it.
var (
	authzReadRoles  = []string{"view-authorization", "manage-authorization", "view-clients", "manage-clients"}
	authzWriteRoles = []string{"manage-authorization", "manage-clients"}
)

// groupsReadRoles is what the group listing and the count accept. Measured
// 2026-08-28 on one caller per role.
//
// **It is not usersReadRoles**, though it differs by one role in each
// direction: query-users is 403 on the group listing where query-groups is 200,
// and the two are otherwise siblings that view-users is composite over. A set
// carried over from the user routes would have been wrong on both.
var groupsReadRoles = []string{"view-users", "manage-users", "query-groups"}

// groupReadRoles is what reading one group, its children and its members
// accept. query-groups opens the listing and the count and none of these.
var groupReadRoles = []string{"view-users", "manage-users"}

// groupWriteRoles is what creating, updating and deleting a group take:
// manage-users alone, measured, like the rest of the user family's writes.
var groupWriteRoles = []string{"manage-users"}

// realmWriteRoles is what PUT and DELETE on a realm take: manage-realm alone,
// measured against all 21 admin roles on a realm created for the sweep. Nothing
// else opens either, and view-realm - which opens the full read - is 403 on
// both. realm-admin is absent because it does not need to be here: it is
// composite over manage-realm and internal/roles expands it.
var realmWriteRoles = []string{"manage-realm"}

// realmRolesReadRoles is what both realm-role reads accept: view-realm or
// manage-realm, measured across eight single-role callers.
var realmRolesReadRoles = []string{"view-realm", "manage-realm"}

// realmConfigReadRoles is what the realm's own configuration reads accept: the
// key set, the default groups listing and both client-policy reads. Measured
// 2026-08-29 across all 22 realm-management roles plus a caller holding none,
// on each of the four routes.
//
// **It holds the same two roles as realmRolesReadRoles and is a second
// variable on purpose.** The two were measured on different routes and agree
// today; sharing one would make a later measurement that splits them look like
// a regression in the other family, which is the mistake usersReadRoles and
// groupsReadRoles already record next door.
var realmConfigReadRoles = []string{"view-realm", "manage-realm"}

// clientRolesReadRoles is what both client-role reads accept: view-clients or
// manage-clients - measured the same way as the realm-role pair above, on an
// ordinary client. GET .../roles answered 200 for both roles.
var clientRolesReadRoles = []string{"view-clients", "manage-clients"}

// requiredActionsListReadRoles is GET .../authentication/required-actions, and
// it is the widest read on its tag by two roles.
//
// Measured across all 21 roles of the target realm's own container plus a
// caller holding none: view-realm, manage-realm, view-users and query-users all
// answer 200, while every other read on the tag - the four registries,
// per-client-config-description, config-description and every
// required-actions/{alias} route - answers 403 to the two users roles.
//
// **It is not the "200 with a shorter list to a weaker caller" pattern** this
// API has three instances of. A query-users caller's body is byte-identical to
// a manage-realm caller's; the admission is genuinely wider rather than the
// body being narrower. So it is a role set and not a filter, and reusing
// realmConfigReadRoles here would refuse two callers Keycloak admits.
//
// It is a separate variable from realmConfigReadRoles for the reason that one
// is separate from realmRolesReadRoles: they were measured on different routes,
// and sharing would make a later split look like a regression.
var requiredActionsListReadRoles = []string{
	"view-realm", "manage-realm", "view-users", "query-users",
}

// flowListReadRoles is GET .../authentication/flows, the tag's **second** wide
// read - and it is wide in a different direction from the first.
//
// Measured 2026-09-03 across all 21 roles of the target realm's own container
// plus a caller holding none: view-realm, manage-realm, **view-clients** and
// **query-clients** answer 200. The required-action listing's two extra roles
// are the *users* pair; this one's are the *clients* pair, and neither list
// opens the other's route. Two wide reads on one tag, four extra roles, no
// overlap - so a single tag-wide slice gets both wrong.
//
// It is wide on this operation **alone**: view-clients is 403 on
// GET /flows/{id} and on GET /flows/{flowAlias}/executions, which are one path
// segment away. And it is not the "200 with a shorter list to a weaker caller"
// pattern - a query-clients caller's body is byte-identical to a manage-realm
// caller's.
var flowListReadRoles = []string{
	"view-realm", "manage-realm", "view-clients", "query-clients",
}

// organizationReadRoles is what the single organization read accepts.
//
// **manage-realm is in it and view-realm is not.** Measured 2026-08-31 with a
// token minted per role, eleven single-role callers against seven requests:
// view-organizations, manage-organizations and manage-realm answer 200, and
// view-realm, view-users, manage-users, view-clients, manage-clients and
// query-groups all answer 403. The realm pair is not a view/manage pair on this
// family - only the manage half reaches - so realmConfigReadRoles is wrong here
// in both directions and is not reused.
var organizationReadRoles = []string{"view-organizations", "manage-organizations", "manage-realm"}

// organizationsListReadRoles is the listing's and the count's, which is the
// read set plus query-organizations.
//
// query-organizations opens **those two and nothing else**: the single read
// answers it 403. That is exactly query-groups' shape on the group listing and
// query-clients' on the client listing, measured on this family rather than
// inherited from either.
var organizationsListReadRoles = []string{
	"view-organizations", "manage-organizations", "manage-realm", "query-organizations",
}

// organizationWriteRoles is what the create, the update and the delete accept.
// view-organizations reads and does not write; manage-realm does both.
//
// It is also the **whole** guard of all four invitation routes, the two reads
// included - see the router. A read that refuses the view role is a shape this
// API has had twice before.
var organizationWriteRoles = []string{"manage-organizations", "manage-realm"}

// organizationMemberListRoles is the *user*-side half of the conjunction the
// member listing and the member count need, on top of an organization role.
//
// **query-users is in it and it opens those two routes and nothing else** -
// the single member read, its groups and its organizations all answer a
// `view-organizations` + `query-users` caller 403 while the listing and the
// count answer 200. That is exactly `GET /users`' role set against
// `GET /users/{id}`'s, reproduced one tag away and measured here rather than
// inherited.
var organizationMemberListRoles = []string{"view-users", "manage-users", "query-users"}

// organizationMemberReadRoles is the same half for the three routes that
// resolve a single member: the read, its groups and its organizations. The
// top-level `.../members/{id}/organizations` takes it too and is unserved for a
// routing reason - see the router.
var organizationMemberReadRoles = []string{"view-users", "manage-users"}

// organizationMemberWriteRoles is the half the member add, the member remove
// and the two invite endpoints need. **It is manage-users alone**:
// `manage-organizations` with `view-users` is 403 on all four, and so is
// `manage-realm` with `view-users`.
var organizationMemberWriteRoles = []string{"manage-users"}

// identityProviderReadRoles is what six of the seven reads on the tag accept.
//
// **The pair is exactly view-identity-providers and manage-identity-providers,
// and nothing else reaches it.** Measured 2026-09-01 with a token minted per
// role, fifteen single-role callers against ten requests: view-realm,
// manage-realm, view-clients, manage-clients, query-clients, query-realms,
// view-users, manage-users, view-authorization, manage-authorization,
// view-organizations, create-client and a caller holding nothing all answer
// 403 on every route in the family. It is the narrowest guard in this package.
var identityProviderReadRoles = []string{
	"view-identity-providers", "manage-identity-providers",
}

// identityProviderWriteRoles is what the create, the update, the delete **and
// `GET .../reload-keys`** accept.
//
// The last of those is the finding: a read that refuses the view role, one of
// two in the whole API. `view-identity-providers` reads the listing, the single
// provider, the export, the mappers, the mapper types and the provider
// catalogue, and is 403 on `reload-keys` alone. Measured one role at a time on
// all seven reads, so it is a difference between siblings rather than between
// families.
var identityProviderWriteRoles = []string{"manage-identity-providers"}

// componentReadRoles is what both component reads accept.
//
// **It is the realm pair and not the identity-provider pair**, although the
// rows this family serves are key providers and client-registration policies
// and although user federation lives here too. Measured on the same fifteen
// single-role callers as the family above, on the same container, in the same
// sweep: view-realm and manage-realm answer 200 and every other role answers
// 403, `manage-identity-providers` included. Two neighbouring chapters, two
// disjoint role pairs, and nothing in the description says so.
var componentReadRoles = []string{"view-realm", "manage-realm"}

// componentWriteRoles is what the two writes, the delete and nothing else
// accept. Measured on the same nine single-role callers as the reads: the three
// answer 201, 204 and 204 for `manage-realm` and 403 for `view-realm`, so the
// family's read/write split is inside one pair rather than across two.
var componentWriteRoles = []string{"manage-realm"}

// bruteForceReadRoles is GET .../attack-detection/brute-force/users/{userId}.
//
// **The Attack Detection tag is authorised out of the users pair**, which
// nothing in its path or its tag says. Measured one role at a time over nine
// callers: `view-users` and `manage-users` answer 200, `query-users` answers
// 403 although it opens `GET /users`, and the realm and clients pairs answer
// 403 too. That is the role-mapping family's shape - view or manage on the
// read, manage alone on the writes - reached from a different chapter.
//
// It is a separate variable from userReadRoles for the reason the realm pairs
// are separate from each other: the two were measured on different routes.
var bruteForceReadRoles = []string{"view-users", "manage-users"}

// bruteForceWriteRoles is both deletes.
var bruteForceWriteRoles = []string{"manage-users"}

// initialAccessReadRoles is GET .../clients-initial-access.
//
// **The Client Initial Access tag is authorised out of the clients pair**, and
// `view-realm` and `manage-realm` are 403 on all three of its routes - measured
// in the same sweep as the component family above, which takes exactly the
// opposite pair. Two chapters landing in one branch, two disjoint role pairs,
// and the description's tag predicts neither.
var initialAccessReadRoles = []string{"view-clients", "manage-clients"}

// initialAccessWriteRoles is the create and the delete.
var initialAccessWriteRoles = []string{"manage-clients"}

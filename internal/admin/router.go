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

	// Client types, whose entire contract on a default 26.7.1 is a 501.
	// CLIENT_TYPES is a disabled preview feature, the same situation as
	// GET .../client-secret/rotated's permanent 404. See guardRealmFeature for
	// why this is not a guardAny with an empty role list.
	mux.HandleFunc("GET /admin/realms/{realm}/client-types", h.guardRealmFeature(writeFeatureNotEnabled))
	mux.HandleFunc("PUT /admin/realms/{realm}/client-types", h.guardRealmFeature(writeFeatureNotEnabled))

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

// Package store defines the persistence boundary. Handlers depend on these
// interfaces and never on a concrete database, which is what lets protocol
// tests run against SQLite with no Docker.
package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ekalinin/gloak/internal/model"
)

var (
	// ErrNotFound is returned when a lookup matches nothing. Handlers map it
	// to Keycloak's 404 shapes.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when a uniqueness constraint is violated.
	// Handlers map it to Keycloak's 409 errorMessage shape.
	ErrConflict = errors.New("store: conflict")
)

// HoldsProtocolMapper reports whether a container's serialised protocol mappers
// hold this id.
//
// It sits here rather than in either driver because both drivers store that
// column as the same JSON, written by the same marshaller, and a scan written
// twice is a scan that can come to disagree - which is the one thing the two
// drivers must not do. It is not SQL and it knows no dialect; it reads the
// bytes a driver has already fetched.
//
// A column that does not parse holds nothing. That cannot happen through any
// write in this repository, and answering "no" for it keeps a corrupt row from
// making an id permanently unusable.
func HoldsProtocolMapper(serialised string, mapperID string) bool {
	var mappers []model.ProtocolMapper
	if err := json.Unmarshal([]byte(serialised), &mappers); err != nil {
		return false
	}
	for _, m := range mappers {
		if m.ID == mapperID {
			return true
		}
	}
	return false
}

type Store interface {
	Realms() RealmRepo
	Clients() ClientRepo
	ClientScopes() ClientScopeRepo
	Users() UserRepo
	Roles() RoleRepo
	Groups() GroupRepo
	Keys() KeyRepo
	Sessions() SessionRepo
	RequiredActions() RequiredActionRepo
	Close() error
}

// RequiredActionRepo stores a realm's registered required action providers.
//
// It is keyed by a server-minted id rather than by alias, and the reason is
// measured rather than tidy: PUT /required-actions/{alias} writes the body's
// alias over the row's, so a PUT with an empty body renames a row to the empty
// string and leaves it in the listing addressable by nothing. See
// 0017_required_action.sql.
type RequiredActionRepo interface {
	// ListByRealm returns every registered required action, ordered by
	// priority ascending. That order is the contract: the listing was measured
	// in priority order on master and on a created realm, and the orphan row a
	// PUT with `{}` leaves behind - priority 0 - sorted first.
	//
	// A tie is broken by id so the two drivers agree with each other. Nothing
	// measured says what Keycloak does with one, because no measured realm has
	// two rows at one priority.
	ListByRealm(ctx context.Context, realmID string) ([]*model.RequiredActionProvider, error)
	// ByAlias resolves one row. An alias that matches nothing is ErrNotFound,
	// which the handlers turn into **two** different 404 bodies depending on
	// the verb - see writeRequiredActionNotFound.
	ByAlias(ctx context.Context, realmID, alias string) (*model.RequiredActionProvider, error)
	Create(ctx context.Context, m *model.RequiredActionProvider) error
	// Update writes alias, name, enabled, defaultAction, priority and config
	// back. It does **not** write providerId: that field is read off the wire
	// by PUT /required-actions/{alias} and discarded, measured, so a row's
	// provider cannot change after registration.
	Update(ctx context.Context, m *model.RequiredActionProvider) error
	Delete(ctx context.Context, realmID, id string) error
}

type RealmRepo interface {
	Create(ctx context.Context, r *model.Realm) error
	ByName(ctx context.Context, name string) (*model.Realm, error)
	// List returns every realm. It is **not sorted**: Keycloak's own listing
	// came back neither alphabetically nor in creation order - ten realms
	// answered `probe-new-3, p4id, p4off, p4c, p4e, p4put, master, p4rich,
	// p4a, p4d`, twice - so the conformance cases compare it unordered and no
	// order here would be the measured one. The ORDER BY is kept only so the
	// two drivers agree with each other.
	List(ctx context.Context) ([]*model.Realm, error)
	// Update writes a realm back, **including its name**: PUT was measured
	// renaming a realm while keeping its id, which no other resource on this
	// API allows - a role can be renamed and a username explicitly cannot.
	// A rename onto a taken name reports ErrConflict, which is the measured
	// 409.
	Update(ctx context.Context, r *model.Realm) error
	// Delete removes a realm and, through the schema's cascades, its clients,
	// users, roles, groups, sessions and keys. Every root table already
	// references realm(id) ON DELETE CASCADE; storetest proves both drivers
	// act on it rather than trusting that the DDL says so.
	Delete(ctx context.Context, id string) error
}

type ClientRepo interface {
	Create(ctx context.Context, c *model.Client) error
	ByClientID(ctx context.Context, realmID, clientID string) (*model.Client, error)
	ByID(ctx context.Context, realmID, id string) (*model.Client, error)
	ListByRealm(ctx context.Context, realmID string) ([]*model.Client, error)
	Update(ctx context.Context, c *model.Client) error
	Delete(ctx context.Context, realmID, id string) error
	// ProtocolMapperOwner returns the id of the client holding this protocol
	// mapper id, and ErrNotFound when none does. It takes **no realm**, and
	// that is the measurement rather than an oversight: a client scope created
	// in one realm carrying a mapper id already in use in another is a 409, so
	// the uniqueness is server-wide. See HoldsProtocolMapper.
	ProtocolMapperOwner(ctx context.Context, mapperID string) (string, error)
}

// ClientScopeRepo stores a realm's client scopes and the two membership sets
// that hang off them: the realm's own defaults, and each client's.
//
// Both memberships are one table with a boolean, not two tables, because
// Keycloak stores them that way and it shows: `PUT
// .../default-client-scopes/{id}` naming a scope the client already holds as an
// **optional** scope answers 204 and moves nothing. Two tables would let a
// scope be in both at once, which no measurement can produce.
type ClientScopeRepo interface {
	Create(ctx context.Context, s *model.ClientScope) error
	ByID(ctx context.Context, realmID, id string) (*model.ClientScope, error)
	ByName(ctx context.Context, realmID, name string) (*model.ClientScope, error)
	// ListByRealm returns every client scope in the realm. Keycloak's own
	// listing order is a Java set's and is not reproducible, so the ORDER BY
	// exists only to make the two drivers agree with each other; the
	// conformance cases compare it unordered.
	ListByRealm(ctx context.Context, realmID string) ([]*model.ClientScope, error)
	// Update writes name, description, protocol, attributes and mappers back.
	// A rename onto a taken name reports ErrConflict, which is the measured
	// 409 `Client Scope <name> already exists`.
	Update(ctx context.Context, s *model.ClientScope) error
	// Delete removes the scope and, through the schema's cascades, its
	// membership of the realm's default sets and of every client's. Measured:
	// deleting a scope that was a realm default and attached to a client left
	// both listings without it.
	Delete(ctx context.Context, realmID, id string) error
	// ProtocolMapperOwner is ClientRepo's, over the other kind of container. A
	// mapper id is unique across the two of them together, so a caller asking
	// whether one is free has to ask both.
	ProtocolMapperOwner(ctx context.Context, mapperID string) (string, error)

	// ListRealmDefaults returns the realm's own default (defaultScope true) or
	// optional (false) client scopes - what a client with no lists of its own
	// inherits, before the protocol filter.
	ListRealmDefaults(ctx context.Context, realmID string, defaultScope bool) ([]*model.ClientScope, error)
	// AddRealmDefault puts a scope into one of the realm's two sets. It reports
	// ErrConflict when the scope is already in **either** of them: the measured
	// 409 fires for a repeat and for a scope moving from one list to the other
	// alike, which is what says the two sets are one row with a flag.
	AddRealmDefault(ctx context.Context, realmID, scopeID string, defaultScope bool) error
	// RemoveRealmDefault takes a scope out of the realm's sets. It does not
	// take the set as an argument on purpose: `DELETE
	// .../default-default-client-scopes/{id}` was measured removing a scope
	// that was in the **optional** list. The path names a list and the delete
	// ignores it.
	RemoveRealmDefault(ctx context.Context, realmID, scopeID string) error

	// ListClientScopes returns a client's default or optional client scopes.
	ListClientScopes(ctx context.Context, clientID string, defaultScope bool) ([]*model.ClientScope, error)
	// AddClientScope attaches a scope to a client. Unlike the realm's, this one
	// is idempotent and silent: attaching twice, and attaching a scope already
	// held in the other list, were both measured answering 204 and changing
	// nothing.
	AddClientScope(ctx context.Context, clientID, scopeID string, defaultScope bool) error
	// RemoveClientScope detaches a scope from a client, ignoring which list the
	// caller's path named - the same asymmetry RemoveRealmDefault records.
	RemoveClientScope(ctx context.Context, clientID, scopeID string) error
}

type UserRepo interface {
	Create(ctx context.Context, u *model.User) error
	ByUsername(ctx context.Context, realmID, username string) (*model.User, error)
	ByID(ctx context.Context, realmID, id string) (*model.User, error)
	// ListByRealm returns every user, ordered by username. The order is
	// measured, not a convenience: Keycloak's listing came back
	// aaa-user, admin, full-user, zzz-user for users created in the reverse
	// order, so it sorts rather than returning insertion order. Filtering and
	// paging stay in the handler, since the query parameters that drive them
	// are the admin API's, not the store's.
	ListByRealm(ctx context.Context, realmID string) ([]*model.User, error)
	Update(ctx context.Context, u *model.User) error
	// Delete removes a user and, through the schema's cascades, its sessions
	// and role assignments. It arrives here rather than with the rest of user
	// management because the cascade is what the role-mapping tests assert:
	// an assignment outliving its user would grant rights to a recycled ID.
	Delete(ctx context.Context, realmID, id string) error
	// SetCredential upserts on (user_id, type), which is what the admin API
	// was measured doing: a reset-password replaces the password credential in
	// place - same id, refreshed createdDate, label cleared - and no path
	// creates a second credential of one type.
	SetCredential(ctx context.Context, c *model.Credential) error
	// CredentialByUser returns the credential a login checks against. It must
	// stay deterministic: it orders by priority and then by id, so a user who
	// somehow held two of a type would still authenticate against the same one
	// every time rather than against whichever row the driver returned first.
	CredentialByUser(ctx context.Context, userID, typ string) (*model.Credential, error)
	ListCredentials(ctx context.Context, userID string) ([]*model.Credential, error)
	CredentialByID(ctx context.Context, userID, id string) (*model.Credential, error)
	DeleteCredential(ctx context.Context, userID, id string) error
	// UpdateCredential writes back the two mutable fields, label and priority.
	// The hash is not among them: nothing but a reset-password may change it,
	// and that goes through SetCredential.
	UpdateCredential(ctx context.Context, c *model.Credential) error
}

// GroupRepo is the group tree and the users in it.
//
// Membership is **direct only**: a user in a child was measured not being a
// member of its parent, so nothing here walks upwards.
//
// The last four methods belong to the membership cut rather than to the tree,
// and they are declared here because the migration carrying the join table
// belongs with the table it joins. A second migration for one join table is
// worse than one wide enough.
type GroupRepo interface {
	Create(ctx context.Context, g *model.Group) error
	ByID(ctx context.Context, realmID, id string) (*model.Group, error)
	// Update writes name and attributes back. It does not move a group: the
	// admin API has no operation that reparents one, and a repo method nobody
	// calls is a method nobody has measured.
	Update(ctx context.Context, g *model.Group) error
	// Delete removes the group and, through the schema's cascade, its whole
	// subtree and every membership in it.
	Delete(ctx context.Context, realmID, id string) error
	// ListTopLevel returns the groups with no parent, which is what
	// GET /groups answers - measured top-level only, while the count beside
	// it counts the whole tree.
	ListTopLevel(ctx context.Context, realmID string) ([]*model.Group, error)
	ListChildren(ctx context.Context, realmID, parentID string) ([]*model.Group, error)
	// ListAll returns every group in the realm at any depth, ordered by name.
	// The count and the search both need the whole tree - the count of a
	// realm with one top-level group and one child was measured answering
	// {"count":2}, and a search matches descendants - so this is one method
	// rather than a COUNT and a walk that could disagree.
	ListAll(ctx context.Context, realmID string) ([]*model.Group, error)
	// Ancestry returns the group and its parents, nearest last, which is what
	// a path is computed from.
	Ancestry(ctx context.Context, realmID, id string) ([]*model.Group, error)

	Members(ctx context.Context, realmID, groupID string) ([]*model.User, error)
	AddMember(ctx context.Context, groupID, userID string) error
	RemoveMember(ctx context.Context, groupID, userID string) error
	ListUserGroups(ctx context.Context, realmID, userID string) ([]*model.Group, error)

	// The realm's default groups. They are here rather than on RealmRepo
	// because every one of the three returns or takes a group, and because
	// deleting a group has to take its default-group row with it - measured,
	// and it is keycloak_group that the cascade hangs off.
	//
	// ListDefaultGroups has **no measured order to reproduce**. Three groups
	// added zzz, aaa, mmm came back in that order, and in another realm a
	// parent added first and a child added second came back child first;
	// neither name, id, path nor insertion order explains both. The ORDER BY
	// is here so the two drivers agree with each other, the same reason
	// RealmRepo.List carries one.
	ListDefaultGroups(ctx context.Context, realmID string) ([]*model.Group, error)
	// AddDefaultGroup is idempotent: the same group added twice was measured
	// answering 204 both times and appearing once.
	AddDefaultGroup(ctx context.Context, realmID, groupID string) error
	// RemoveDefaultGroup reports no error for a group that is not a default
	// group, the way RemoveMember does - measured 204 on the second delete.
	RemoveDefaultGroup(ctx context.Context, realmID, groupID string) error
}

type RoleRepo interface {
	Create(ctx context.Context, r *model.Role) error
	ByID(ctx context.Context, realmID, id string) (*model.Role, error)
	ByName(ctx context.Context, realmID, clientID, name string) (*model.Role, error)
	ListRealmRoles(ctx context.Context, realmID string) ([]*model.Role, error)
	// ListClientRoles returns the roles a client owns. Keycloak keeps admin
	// rights on a client - master-realm for the master realm - so this is not
	// a corner of the model but the main route to an authorization decision.
	ListClientRoles(ctx context.Context, realmID, clientID string) ([]*model.Role, error)

	// AddComposite makes childRoleID part of roleID. The bootstrapped
	// administrator holds no client roles directly: measured, every right it
	// has arrives through the admin role's 22 composites, so a caller that
	// does not expand these transitively sees an administrator with nothing.
	AddComposite(ctx context.Context, roleID, childRoleID string) error
	ListComposites(ctx context.Context, roleID string) ([]*model.Role, error)
	// RemoveComposite is AddComposite's inverse. Removing one that is not
	// there reports no error: DELETE .../composites was measured answering
	// 204 for a role that was never a child.
	RemoveComposite(ctx context.Context, roleID, childRoleID string) error

	AssignToUser(ctx context.Context, userID, roleID string) error
	RemoveFromUser(ctx context.Context, userID, roleID string) error
	ListUserRoles(ctx context.Context, userID string) ([]*model.Role, error)

	// The group mirror of the three above. A second table rather than a
	// nullable holder column on one: the two are read by different routes with
	// different guards, and one table invites a query that forgets which kind
	// of holder it meant.
	AssignToGroup(ctx context.Context, groupID, roleID string) error
	RemoveFromGroup(ctx context.Context, groupID, roleID string) error
	ListGroupRoles(ctx context.Context, groupID string) ([]*model.Role, error)
	// ListUsersWithRole returns the users holding this role **directly**.
	// Measured: /roles/{name}/users lists the administrator for `admin` and
	// nobody for `create-realm`, which `admin` is composite over, so this must
	// not expand composites the way internal/roles.Effective does.
	ListUsersWithRole(ctx context.Context, realmID, roleID string) ([]*model.User, error)

	// A **client's** scope mappings: the roles that survive into a token it
	// issues. Not a role the client holds - nothing holds these - so they are a
	// third pair of tables beside the user's and the group's rather than a
	// third kind of holder on either.
	//
	// Both verbs are measured idempotent, on both containers: adding a role
	// already mapped is 204 and removing one that is not mapped is 204. So the
	// add swallows a conflict and the remove swallows a missing row - the group
	// mirror's shape, not the user's.
	AddClientScopeMapping(ctx context.Context, clientID, roleID string) error
	RemoveClientScopeMapping(ctx context.Context, clientID, roleID string) error
	ListClientScopeMappings(ctx context.Context, clientID string) ([]*model.Role, error)

	// A **client scope's** scope mappings. `Scope` twice is deliberate: the
	// container is a client scope and the thing stored is a scope mapping, and
	// the two words carry different halves of that.
	AddClientScopeScopeMapping(ctx context.Context, clientScopeID, roleID string) error
	RemoveClientScopeScopeMapping(ctx context.Context, clientScopeID, roleID string) error
	ListClientScopeScopeMappings(ctx context.Context, clientScopeID string) ([]*model.Role, error)

	// Update writes a role back whole: name, description and attributes are
	// all replaced by what the caller holds. It replaces rather than merging
	// because PUT on a role does - measured, and the opposite of PUT on a
	// client or a user. Renaming through it is legitimate; the id does not
	// change.
	Update(ctx context.Context, r *model.Role) error
	// Delete removes the role **and resyncs the composite flag of any parent
	// whose last child it was**. The composite_role rows cascade, but the flag
	// is a column on the parent, so without this a deleted child leaves its
	// parent answering `"composite":true` beside an empty composites listing.
	// The flag is derived - true exactly when the role has children - and
	// putting the resync here rather than in the three handlers that delete a
	// role makes staleness impossible for every caller.
	Delete(ctx context.Context, realmID, id string) error
}

// SessionRepo stores SSO sessions. A user session is addressed by realm as
// well as by ID: a session ID arrives in a token, and a token minted for one
// realm must never resolve a session in another.
type SessionRepo interface {
	CreateUserSession(ctx context.Context, s *model.UserSession) error
	UserSessionByID(ctx context.Context, realmID, id string) (*model.UserSession, error)
	TouchUserSession(ctx context.Context, id string, lastRefresh int64) error
	DeleteUserSession(ctx context.Context, realmID, id string) error
	// DeleteUserSessions removes every session a user holds, which is what
	// POST /users/{id}/logout does. It reports no error when there are none:
	// the endpoint was measured answering 204 for a user who is already
	// logged out, so "nothing to delete" is a success.
	DeleteUserSessions(ctx context.Context, realmID, userID string) error
	CreateClientSession(ctx context.Context, s *model.ClientSession) error
	ClientSession(ctx context.Context, userSessionID, clientID string) (*model.ClientSession, error)
}

// KeyRepo stores a realm's signing material. There is no update method: a key
// is created once and read back, and rotation - which Keycloak models as a
// second active key rather than a mutation - is not P1.
type KeyRepo interface {
	Create(ctx context.Context, k *model.RealmKey) error
	ListByRealm(ctx context.Context, realmID string) ([]*model.RealmKey, error)
}

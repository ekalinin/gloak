// Package store defines the persistence boundary. Handlers depend on these
// interfaces and never on a concrete database, which is what lets protocol
// tests run against SQLite with no Docker.
package store

import (
	"context"
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

type Store interface {
	Realms() RealmRepo
	Clients() ClientRepo
	Users() UserRepo
	Roles() RoleRepo
	Groups() GroupRepo
	Keys() KeyRepo
	Sessions() SessionRepo
	Close() error
}

type RealmRepo interface {
	Create(ctx context.Context, r *model.Realm) error
	ByName(ctx context.Context, name string) (*model.Realm, error)
	List(ctx context.Context) ([]*model.Realm, error)
}

type ClientRepo interface {
	Create(ctx context.Context, c *model.Client) error
	ByClientID(ctx context.Context, realmID, clientID string) (*model.Client, error)
	ByID(ctx context.Context, realmID, id string) (*model.Client, error)
	ListByRealm(ctx context.Context, realmID string) ([]*model.Client, error)
	Update(ctx context.Context, c *model.Client) error
	Delete(ctx context.Context, realmID, id string) error
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

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
}

type UserRepo interface {
	Create(ctx context.Context, u *model.User) error
	ByUsername(ctx context.Context, realmID, username string) (*model.User, error)
	ByID(ctx context.Context, realmID, id string) (*model.User, error)
	// Delete removes a user and, through the schema's cascades, its sessions
	// and role assignments. It arrives here rather than with the rest of user
	// management because the cascade is what the role-mapping tests assert:
	// an assignment outliving its user would grant rights to a recycled ID.
	Delete(ctx context.Context, realmID, id string) error
	SetCredential(ctx context.Context, c *model.Credential) error
	CredentialByUser(ctx context.Context, userID, typ string) (*model.Credential, error)
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

	AssignToUser(ctx context.Context, userID, roleID string) error
	RemoveFromUser(ctx context.Context, userID, roleID string) error
	ListUserRoles(ctx context.Context, userID string) ([]*model.Role, error)
}

// SessionRepo stores SSO sessions. A user session is addressed by realm as
// well as by ID: a session ID arrives in a token, and a token minted for one
// realm must never resolve a session in another.
type SessionRepo interface {
	CreateUserSession(ctx context.Context, s *model.UserSession) error
	UserSessionByID(ctx context.Context, realmID, id string) (*model.UserSession, error)
	TouchUserSession(ctx context.Context, id string, lastRefresh int64) error
	DeleteUserSession(ctx context.Context, realmID, id string) error
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

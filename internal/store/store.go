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
	SetCredential(ctx context.Context, c *model.Credential) error
	CredentialByUser(ctx context.Context, userID, typ string) (*model.Credential, error)
}

type RoleRepo interface {
	Create(ctx context.Context, r *model.Role) error
	ByName(ctx context.Context, realmID, clientID, name string) (*model.Role, error)
	ListRealmRoles(ctx context.Context, realmID string) ([]*model.Role, error)
}

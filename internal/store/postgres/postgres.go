// Package postgres implements store.Store on pgx/v5 against PostgreSQL. It
// mirrors the sqlite driver method for method so the two stay behaviourally
// identical against the same conformance suite.
package postgres

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct{ pool *pgxpool.Pool }

// Open connects to dsn and applies all migrations.
func Open(ctx context.Context, dsn string) (store.Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	if err := waitReady(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// waitReady tolerates the short window right after a Postgres server starts
// accepting TCP connections but before it is ready to serve queries (for
// example, while a freshly started container's listener is still coming up).
// It is a no-op once the first ping succeeds, which is immediate against an
// already-warm server.
func waitReady(ctx context.Context, pool *pgxpool.Pool) error {
	const (
		attempts = 40
		delay    = 250 * time.Millisecond
	)
	var err error
	for i := 0; i < attempts; i++ {
		if err = pool.Ping(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("postgres: not reachable: %w", ctx.Err())
		case <-time.After(delay):
		}
	}
	return fmt.Errorf("postgres: not reachable after %d attempts: %w", attempts, err)
}

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("postgres: read migrations: %w", err)
	}
	for _, e := range entries {
		b, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("postgres: read %s: %w", e.Name(), err)
		}
		if _, err := pool.Exec(ctx, string(b)); err != nil {
			return fmt.Errorf("postgres: apply %s: %w", e.Name(), err)
		}
	}
	return nil
}

func (s *Store) Close() error {
	s.pool.Close()
	return nil
}
func (s *Store) Realms() store.RealmRepo   { return &realmRepo{s.pool} }
func (s *Store) Clients() store.ClientRepo { return &clientRepo{s.pool} }
func (s *Store) Users() store.UserRepo     { return &userRepo{s.pool} }
func (s *Store) Roles() store.RoleRepo     { return &roleRepo{s.pool} }

// classify maps driver errors onto the store's sentinels so handlers never
// inspect driver-specific error text.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return store.ErrConflict
	}
	return err
}

func encode(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic("postgres: encoding a value that must be encodable: " + err.Error())
	}
	return string(b)
}

func decode(s string, v any) error { return json.Unmarshal([]byte(s), v) }

// scanner is satisfied by both pgx.Row and pgx.Rows, so single-row getters
// and list methods share one scan implementation per entity.
type scanner interface{ Scan(dest ...any) error }

type realmRepo struct{ pool *pgxpool.Pool }

func (r *realmRepo) Create(ctx context.Context, m *model.Realm) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO realm (id, name, enabled, access_token_lifespan, refresh_token_lifespan)
		 VALUES ($1, $2, $3, $4, $5)`,
		m.ID, m.Name, m.Enabled, int64(m.AccessTokenLifespan.Seconds()), int64(m.RefreshTokenLifespan.Seconds()))
	return classify(err)
}

func (r *realmRepo) ByName(ctx context.Context, name string) (*model.Realm, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, name, enabled, access_token_lifespan, refresh_token_lifespan
		 FROM realm WHERE name = $1`, name)
	return scanRealm(row)
}

func (r *realmRepo) List(ctx context.Context) ([]*model.Realm, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, enabled, access_token_lifespan, refresh_token_lifespan
		 FROM realm ORDER BY name`)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()

	var out []*model.Realm
	for rows.Next() {
		m, err := scanRealm(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

func scanRealm(row scanner) (*model.Realm, error) {
	m := &model.Realm{}
	var accessSeconds, refreshSeconds int64
	if err := row.Scan(&m.ID, &m.Name, &m.Enabled, &accessSeconds, &refreshSeconds); err != nil {
		return nil, classify(err)
	}
	m.AccessTokenLifespan = time.Duration(accessSeconds) * time.Second
	m.RefreshTokenLifespan = time.Duration(refreshSeconds) * time.Second
	return m, nil
}

type clientRepo struct{ pool *pgxpool.Pool }

func (r *clientRepo) Create(ctx context.Context, m *model.Client) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO client (id, realm_id, client_id, name, enabled, public_client, secret,
		 standard_flow_enabled, direct_access_grants_enabled, service_accounts_enabled,
		 redirect_uris, web_origins, attributes)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		m.ID, m.RealmID, m.ClientID, m.Name, m.Enabled, m.PublicClient, m.Secret,
		m.StandardFlowEnabled, m.DirectAccessGrantsEnabled, m.ServiceAccountsEnabled,
		encode(m.RedirectURIs), encode(m.WebOrigins), encode(m.Attributes))
	return classify(err)
}

func (r *clientRepo) ByClientID(ctx context.Context, realmID, clientID string) (*model.Client, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, client_id, name, enabled, public_client, secret,
		 standard_flow_enabled, direct_access_grants_enabled, service_accounts_enabled,
		 redirect_uris, web_origins, attributes
		 FROM client WHERE realm_id = $1 AND client_id = $2`, realmID, clientID)
	return scanClient(row)
}

func (r *clientRepo) ByID(ctx context.Context, realmID, id string) (*model.Client, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, client_id, name, enabled, public_client, secret,
		 standard_flow_enabled, direct_access_grants_enabled, service_accounts_enabled,
		 redirect_uris, web_origins, attributes
		 FROM client WHERE realm_id = $1 AND id = $2`, realmID, id)
	return scanClient(row)
}

func (r *clientRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.Client, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, realm_id, client_id, name, enabled, public_client, secret,
		 standard_flow_enabled, direct_access_grants_enabled, service_accounts_enabled,
		 redirect_uris, web_origins, attributes
		 FROM client WHERE realm_id = $1 ORDER BY client_id`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()

	var out []*model.Client
	for rows.Next() {
		m, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

func scanClient(row scanner) (*model.Client, error) {
	m := &model.Client{}
	var redirectURIs, webOrigins, attributes string
	err := row.Scan(&m.ID, &m.RealmID, &m.ClientID, &m.Name, &m.Enabled, &m.PublicClient, &m.Secret,
		&m.StandardFlowEnabled, &m.DirectAccessGrantsEnabled, &m.ServiceAccountsEnabled,
		&redirectURIs, &webOrigins, &attributes)
	if err != nil {
		return nil, classify(err)
	}
	if err := decode(redirectURIs, &m.RedirectURIs); err != nil {
		return nil, fmt.Errorf("postgres: decode redirect_uris: %w", err)
	}
	if err := decode(webOrigins, &m.WebOrigins); err != nil {
		return nil, fmt.Errorf("postgres: decode web_origins: %w", err)
	}
	if err := decode(attributes, &m.Attributes); err != nil {
		return nil, fmt.Errorf("postgres: decode attributes: %w", err)
	}
	return m, nil
}

type userRepo struct{ pool *pgxpool.Pool }

func (r *userRepo) Create(ctx context.Context, m *model.User) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO user_entity (id, realm_id, username, email, email_verified, enabled,
		 first_name, last_name, created_timestamp, attributes)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		m.ID, m.RealmID, m.Username, m.Email, m.EmailVerified, m.Enabled,
		m.FirstName, m.LastName, m.CreatedTimestamp, encode(m.Attributes))
	return classify(err)
}

func (r *userRepo) ByUsername(ctx context.Context, realmID, username string) (*model.User, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, username, email, email_verified, enabled, first_name, last_name,
		 created_timestamp, attributes
		 FROM user_entity WHERE realm_id = $1 AND username = $2`, realmID, username)
	return scanUser(row)
}

func (r *userRepo) ByID(ctx context.Context, realmID, id string) (*model.User, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, username, email, email_verified, enabled, first_name, last_name,
		 created_timestamp, attributes
		 FROM user_entity WHERE realm_id = $1 AND id = $2`, realmID, id)
	return scanUser(row)
}

// SetCredential upserts on (user_id, type) so a password reset can replace an
// existing credential of the same type without a separate delete.
func (r *userRepo) SetCredential(ctx context.Context, m *model.Credential) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO credential (id, user_id, type, created_date, algorithm, hash_iterations,
		 additional_parameters, salt, hash_value)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (user_id, type) DO UPDATE SET
		 	created_date = excluded.created_date,
		 	algorithm = excluded.algorithm,
		 	hash_iterations = excluded.hash_iterations,
		 	additional_parameters = excluded.additional_parameters,
		 	salt = excluded.salt,
		 	hash_value = excluded.hash_value`,
		m.ID, m.UserID, m.Type, m.CreatedDate, m.Algorithm, m.HashIterations,
		encode(m.AdditionalParameters), m.Salt, m.HashValue)
	return classify(err)
}

func (r *userRepo) CredentialByUser(ctx context.Context, userID, typ string) (*model.Credential, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, user_id, type, created_date, algorithm, hash_iterations, additional_parameters, salt, hash_value
		 FROM credential WHERE user_id = $1 AND type = $2`, userID, typ)
	return scanCredential(row)
}

func scanUser(row scanner) (*model.User, error) {
	m := &model.User{}
	var attributes string
	err := row.Scan(&m.ID, &m.RealmID, &m.Username, &m.Email, &m.EmailVerified, &m.Enabled,
		&m.FirstName, &m.LastName, &m.CreatedTimestamp, &attributes)
	if err != nil {
		return nil, classify(err)
	}
	if err := decode(attributes, &m.Attributes); err != nil {
		return nil, fmt.Errorf("postgres: decode attributes: %w", err)
	}
	return m, nil
}

func scanCredential(row scanner) (*model.Credential, error) {
	m := &model.Credential{}
	var additionalParameters string
	err := row.Scan(&m.ID, &m.UserID, &m.Type, &m.CreatedDate, &m.Algorithm, &m.HashIterations,
		&additionalParameters, &m.Salt, &m.HashValue)
	if err != nil {
		return nil, classify(err)
	}
	if err := decode(additionalParameters, &m.AdditionalParameters); err != nil {
		return nil, fmt.Errorf("postgres: decode additional_parameters: %w", err)
	}
	return m, nil
}

type roleRepo struct{ pool *pgxpool.Pool }

func (r *roleRepo) Create(ctx context.Context, m *model.Role) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO keycloak_role (id, realm_id, client_id, name, description, composite)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		m.ID, m.RealmID, m.ClientID, m.Name, m.Description, m.Composite)
	return classify(err)
}

func (r *roleRepo) ByName(ctx context.Context, realmID, clientID, name string) (*model.Role, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = $1 AND client_id = $2 AND name = $3`, realmID, clientID, name)
	return scanRole(row)
}

// ListRealmRoles returns realm-level roles, which are stored with an empty
// client_id; client roles are excluded.
func (r *roleRepo) ListRealmRoles(ctx context.Context, realmID string) ([]*model.Role, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = $1 AND client_id = '' ORDER BY name`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()

	var out []*model.Role
	for rows.Next() {
		m, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

func scanRole(row scanner) (*model.Role, error) {
	m := &model.Role{}
	if err := row.Scan(&m.ID, &m.RealmID, &m.ClientID, &m.Name, &m.Description, &m.Composite); err != nil {
		return nil, classify(err)
	}
	return m, nil
}

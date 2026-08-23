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
	"sort"
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
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// migrate applies every migration file not yet recorded in
// schema_migrations, in filename order, so Open is safe to call again
// against a database that is already fully migrated - the situation every
// server restart hits.
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		filename   TEXT PRIMARY KEY,
		applied_at BIGINT NOT NULL
	)`); err != nil {
		return fmt.Errorf("postgres: create schema_migrations: %w", err)
	}

	applied, err := appliedMigrations(ctx, pool)
	if err != nil {
		return err
	}

	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("postgres: read migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		if applied[e.Name()] {
			continue
		}
		b, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("postgres: read %s: %w", e.Name(), err)
		}
		if err := applyMigration(ctx, pool, e.Name(), string(b)); err != nil {
			return err
		}
	}
	return nil
}

// appliedMigrations returns the set of migration filenames already recorded
// in schema_migrations.
func appliedMigrations(ctx context.Context, pool *pgxpool.Pool) (map[string]bool, error) {
	rows, err := pool.Query(ctx, `SELECT filename FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("postgres: read schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("postgres: scan schema_migrations: %w", err)
		}
		applied[name] = true
	}
	return applied, rows.Err()
}

// applyMigration runs one migration file's SQL and records it as applied
// within the same transaction, so a crash between the two can never leave a
// migration recorded as applied without having actually run.
func applyMigration(ctx context.Context, pool *pgxpool.Pool, name, sqlText string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin %s: %w", name, err)
	}
	defer tx.Rollback(ctx) // no-op once Commit has succeeded

	if _, err := tx.Exec(ctx, sqlText); err != nil {
		return fmt.Errorf("postgres: apply %s: %w", name, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (filename, applied_at) VALUES ($1, $2)`,
		name, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("postgres: record %s: %w", name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit %s: %w", name, err)
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
func (s *Store) Keys() store.KeyRepo       { return &keyRepo{s.pool} }

func (s *Store) Sessions() store.SessionRepo { return &sessionRepo{s.pool} }

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
		`INSERT INTO client (id, realm_id, client_id, name, root_url, base_url, enabled, public_client, secret,
		 protocol, client_authenticator_type, surrogate_auth_required, always_display_in_console,
		 bearer_only, consent_required, standard_flow_enabled, implicit_flow_enabled,
		 direct_access_grants_enabled, service_accounts_enabled, frontchannel_logout,
		 full_scope_allowed, not_before, node_re_registration_timeout,
		 redirect_uris, web_origins, default_client_scopes, optional_client_scopes, attributes)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)`,
		m.ID, m.RealmID, m.ClientID, m.Name, m.RootURL, m.BaseURL, m.Enabled, m.PublicClient, m.Secret,
		m.Protocol, m.ClientAuthenticatorType, m.SurrogateAuthRequired, m.AlwaysDisplayInConsole,
		m.BearerOnly, m.ConsentRequired, m.StandardFlowEnabled, m.ImplicitFlowEnabled,
		m.DirectAccessGrantsEnabled, m.ServiceAccountsEnabled, m.FrontchannelLogout,
		m.FullScopeAllowed, m.NotBefore, m.NodeReRegistrationTimeout,
		encode(m.RedirectURIs), encode(m.WebOrigins), encode(m.DefaultClientScopes),
		encode(m.OptionalClientScopes), encode(m.Attributes))
	return classify(err)
}

func (r *clientRepo) ByClientID(ctx context.Context, realmID, clientID string) (*model.Client, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, client_id, name, root_url, base_url, enabled, public_client, secret,
		 protocol, client_authenticator_type, surrogate_auth_required, always_display_in_console,
		 bearer_only, consent_required, standard_flow_enabled, implicit_flow_enabled,
		 direct_access_grants_enabled, service_accounts_enabled, frontchannel_logout,
		 full_scope_allowed, not_before, node_re_registration_timeout,
		 redirect_uris, web_origins, default_client_scopes, optional_client_scopes, attributes
		 FROM client WHERE realm_id = $1 AND client_id = $2`, realmID, clientID)
	return scanClient(row)
}

func (r *clientRepo) ByID(ctx context.Context, realmID, id string) (*model.Client, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, client_id, name, root_url, base_url, enabled, public_client, secret,
		 protocol, client_authenticator_type, surrogate_auth_required, always_display_in_console,
		 bearer_only, consent_required, standard_flow_enabled, implicit_flow_enabled,
		 direct_access_grants_enabled, service_accounts_enabled, frontchannel_logout,
		 full_scope_allowed, not_before, node_re_registration_timeout,
		 redirect_uris, web_origins, default_client_scopes, optional_client_scopes, attributes
		 FROM client WHERE realm_id = $1 AND id = $2`, realmID, id)
	return scanClient(row)
}

func (r *clientRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.Client, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, realm_id, client_id, name, root_url, base_url, enabled, public_client, secret,
		 protocol, client_authenticator_type, surrogate_auth_required, always_display_in_console,
		 bearer_only, consent_required, standard_flow_enabled, implicit_flow_enabled,
		 direct_access_grants_enabled, service_accounts_enabled, frontchannel_logout,
		 full_scope_allowed, not_before, node_re_registration_timeout,
		 redirect_uris, web_origins, default_client_scopes, optional_client_scopes, attributes
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

// Update replaces every mutable column. The admin API's PUT carries a whole
// representation, and merge semantics are applied above this layer.
func (r *clientRepo) Update(ctx context.Context, m *model.Client) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE client SET
			 name = $1, root_url = $2, base_url = $3, enabled = $4, public_client = $5, secret = $6,
			 protocol = $7, client_authenticator_type = $8, surrogate_auth_required = $9,
			 always_display_in_console = $10, bearer_only = $11, consent_required = $12,
			 standard_flow_enabled = $13, implicit_flow_enabled = $14, direct_access_grants_enabled = $15,
			 service_accounts_enabled = $16, frontchannel_logout = $17, full_scope_allowed = $18,
			 not_before = $19, node_re_registration_timeout = $20,
			 redirect_uris = $21, web_origins = $22, default_client_scopes = $23,
			 optional_client_scopes = $24, attributes = $25
			 WHERE realm_id = $26 AND id = $27`,
		m.Name, m.RootURL, m.BaseURL, m.Enabled, m.PublicClient, m.Secret,
		m.Protocol, m.ClientAuthenticatorType, m.SurrogateAuthRequired,
		m.AlwaysDisplayInConsole, m.BearerOnly, m.ConsentRequired,
		m.StandardFlowEnabled, m.ImplicitFlowEnabled, m.DirectAccessGrantsEnabled,
		m.ServiceAccountsEnabled, m.FrontchannelLogout, m.FullScopeAllowed,
		m.NotBefore, m.NodeReRegistrationTimeout,
		encode(m.RedirectURIs), encode(m.WebOrigins), encode(m.DefaultClientScopes),
		encode(m.OptionalClientScopes), encode(m.Attributes),
		m.RealmID, m.ID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

func (r *clientRepo) Delete(ctx context.Context, realmID, id string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM client WHERE realm_id = $1 AND id = $2`, realmID, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

func scanClient(row scanner) (*model.Client, error) {
	m := &model.Client{}
	var redirectURIs, webOrigins, defaultScopes, optionalScopes, attributes string
	err := row.Scan(&m.ID, &m.RealmID, &m.ClientID, &m.Name, &m.RootURL, &m.BaseURL,
		&m.Enabled, &m.PublicClient, &m.Secret,
		&m.Protocol, &m.ClientAuthenticatorType, &m.SurrogateAuthRequired, &m.AlwaysDisplayInConsole,
		&m.BearerOnly, &m.ConsentRequired, &m.StandardFlowEnabled, &m.ImplicitFlowEnabled,
		&m.DirectAccessGrantsEnabled, &m.ServiceAccountsEnabled, &m.FrontchannelLogout,
		&m.FullScopeAllowed, &m.NotBefore, &m.NodeReRegistrationTimeout,
		&redirectURIs, &webOrigins, &defaultScopes, &optionalScopes, &attributes)
	if err != nil {
		return nil, classify(err)
	}
	for _, f := range []struct {
		raw  string
		into any
		name string
	}{
		{redirectURIs, &m.RedirectURIs, "redirect_uris"},
		{webOrigins, &m.WebOrigins, "web_origins"},
		{defaultScopes, &m.DefaultClientScopes, "default_client_scopes"},
		{optionalScopes, &m.OptionalClientScopes, "optional_client_scopes"},
		{attributes, &m.Attributes, "attributes"},
	} {
		if err := decode(f.raw, f.into); err != nil {
			return nil, fmt.Errorf("postgres: decode %s: %w", f.name, err)
		}
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

// ListByRealm orders by username because Keycloak's listing was measured
// sorted rather than in insertion order.
func (r *userRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.User, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, realm_id, username, email, email_verified, enabled, first_name, last_name,
		 created_timestamp, attributes
		 FROM user_entity WHERE realm_id = $1 ORDER BY username`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()

	var out []*model.User
	for rows.Next() {
		m, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

func (r *userRepo) Delete(ctx context.Context, realmID, id string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM user_entity WHERE realm_id = $1 AND id = $2`, realmID, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
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

func (r *roleRepo) ByID(ctx context.Context, realmID, id string) (*model.Role, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = $1 AND id = $2`, realmID, id)
	return scanRole(row)
}

// ListClientRoles returns the roles a client owns, the counterpart of
// ListRealmRoles' empty-client_id filter.
func (r *roleRepo) ListClientRoles(ctx context.Context, realmID, clientID string) ([]*model.Role, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = $1 AND client_id = $2 ORDER BY name`, realmID, clientID)
	if err != nil {
		return nil, classify(err)
	}
	return collectRoles(rows)
}

func (r *roleRepo) AddComposite(ctx context.Context, roleID, childRoleID string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO composite_role (composite, child_role) VALUES ($1, $2)`, roleID, childRoleID)
	return classify(err)
}

func (r *roleRepo) ListComposites(ctx context.Context, roleID string) ([]*model.Role, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT r.id, r.realm_id, r.client_id, r.name, r.description, r.composite
		 FROM keycloak_role r
		 JOIN composite_role c ON c.child_role = r.id
		 WHERE c.composite = $1 ORDER BY r.name`, roleID)
	if err != nil {
		return nil, classify(err)
	}
	return collectRoles(rows)
}

func (r *roleRepo) AssignToUser(ctx context.Context, userID, roleID string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO user_role_mapping (user_id, role_id) VALUES ($1, $2)`, userID, roleID)
	return classify(err)
}

func (r *roleRepo) RemoveFromUser(ctx context.Context, userID, roleID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM user_role_mapping WHERE user_id = $1 AND role_id = $2`, userID, roleID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

func (r *roleRepo) ListUserRoles(ctx context.Context, userID string) ([]*model.Role, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT r.id, r.realm_id, r.client_id, r.name, r.description, r.composite
		 FROM keycloak_role r
		 JOIN user_role_mapping m ON m.role_id = r.id
		 WHERE m.user_id = $1 ORDER BY r.name`, userID)
	if err != nil {
		return nil, classify(err)
	}
	return collectRoles(rows)
}

// collectRoles drains a role query. Every role listing scans the same six
// columns, so the loop lives once.
func collectRoles(rows pgx.Rows) ([]*model.Role, error) {
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

type keyRepo struct{ pool *pgxpool.Pool }

func (r *keyRepo) Create(ctx context.Context, m *model.RealmKey) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO realm_key (id, realm_id, algorithm, key_use, private_key, certificate, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		m.ID, m.RealmID, m.Algorithm, m.Use, m.PrivateKey, m.Certificate, m.CreatedAt)
	return classify(err)
}

func (r *keyRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.RealmKey, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, realm_id, algorithm, key_use, private_key, certificate, created_at
		 FROM realm_key WHERE realm_id = $1 ORDER BY algorithm`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()

	var out []*model.RealmKey
	for rows.Next() {
		m, err := scanRealmKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

type sessionRepo struct{ pool *pgxpool.Pool }

func (r *sessionRepo) CreateUserSession(ctx context.Context, m *model.UserSession) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO user_session (id, realm_id, user_id, username, started_at, last_refresh, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		m.ID, m.RealmID, m.UserID, m.Username, m.StartedAt, m.LastRefresh, m.ExpiresAt)
	return classify(err)
}

func (r *sessionRepo) UserSessionByID(ctx context.Context, realmID, id string) (*model.UserSession, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, user_id, username, started_at, last_refresh, expires_at
		 FROM user_session WHERE realm_id = $1 AND id = $2`, realmID, id)
	return scanUserSession(row)
}

// TouchUserSession records a refresh. It reports ErrNotFound when it matches
// no row: the driver treats an update affecting nothing as success, so without
// this check a refresh against a revoked session would look like it worked.
func (r *sessionRepo) TouchUserSession(ctx context.Context, id string, lastRefresh int64) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE user_session SET last_refresh = $1 WHERE id = $2`, lastRefresh, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

// DeleteUserSession removes the session and, through the schema's cascade, the
// client sessions hanging off it.
func (r *sessionRepo) DeleteUserSession(ctx context.Context, realmID, id string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM user_session WHERE realm_id = $1 AND id = $2`, realmID, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

func (r *sessionRepo) CreateClientSession(ctx context.Context, m *model.ClientSession) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO client_session (id, user_session_id, client_id, scope, started_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		m.ID, m.UserSessionID, m.ClientID, m.Scope, m.StartedAt)
	return classify(err)
}

func (r *sessionRepo) ClientSession(ctx context.Context, userSessionID, clientID string) (*model.ClientSession, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, user_session_id, client_id, scope, started_at
		 FROM client_session WHERE user_session_id = $1 AND client_id = $2`, userSessionID, clientID)
	return scanClientSession(row)
}

// affectedOne turns "this statement changed nothing" into ErrNotFound.
func affectedOne(n int64) error {
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func scanUserSession(row scanner) (*model.UserSession, error) {
	m := &model.UserSession{}
	if err := row.Scan(&m.ID, &m.RealmID, &m.UserID, &m.Username,
		&m.StartedAt, &m.LastRefresh, &m.ExpiresAt); err != nil {
		return nil, classify(err)
	}
	return m, nil
}

func scanClientSession(row scanner) (*model.ClientSession, error) {
	m := &model.ClientSession{}
	if err := row.Scan(&m.ID, &m.UserSessionID, &m.ClientID, &m.Scope, &m.StartedAt); err != nil {
		return nil, classify(err)
	}
	return m, nil
}

func scanRealmKey(row scanner) (*model.RealmKey, error) {
	m := &model.RealmKey{}
	if err := row.Scan(&m.ID, &m.RealmID, &m.Algorithm, &m.Use,
		&m.PrivateKey, &m.Certificate, &m.CreatedAt); err != nil {
		return nil, classify(err)
	}
	return m, nil
}

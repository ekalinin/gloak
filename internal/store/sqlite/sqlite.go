// Package sqlite implements store.Store on modernc.org/sqlite, a cgo-free
// driver, so the binary stays a single static file.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct{ db *sql.DB }

// Open opens the database at dsn and applies all migrations.
func Open(ctx context.Context, dsn string) (store.Store, error) {
	db, err := sql.Open("sqlite", withForeignKeysPragma(dsn))
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// withForeignKeysPragma appends the _pragma=foreign_keys(1) query parameter
// modernc.org/sqlite reads to enable foreign key enforcement, joining it
// with "&" when dsn already carries a query string and "?" otherwise. A
// naive dsn+"?_pragma=..." concatenation produces a second "?" whenever the
// caller's DSN already has one (for example "file:x.db?cache=shared"); the
// driver's query parser then folds everything after the first "&" (there is
// none) into the value of the first parameter, so the pragma is silently
// dropped rather than rejected outright - foreign key constraints stop
// being enforced with no error to notice.
func withForeignKeysPragma(dsn string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=foreign_keys(1)"
}

// migrate applies every migration file not yet recorded in
// schema_migrations, in filename order, so Open is safe to call again
// against a database that is already fully migrated - the situation every
// server restart hits.
func migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		filename   TEXT PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("sqlite: create schema_migrations: %w", err)
	}

	applied, err := appliedMigrations(ctx, db)
	if err != nil {
		return err
	}

	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("sqlite: read migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		if applied[e.Name()] {
			continue
		}
		b, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("sqlite: read %s: %w", e.Name(), err)
		}
		if err := applyMigration(ctx, db, e.Name(), string(b)); err != nil {
			return err
		}
	}
	return nil
}

// appliedMigrations returns the set of migration filenames already recorded
// in schema_migrations.
func appliedMigrations(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT filename FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: read schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("sqlite: scan schema_migrations: %w", err)
		}
		applied[name] = true
	}
	return applied, rows.Err()
}

// applyMigration runs one migration file's SQL and records it as applied
// within the same transaction, so a crash between the two can never leave a
// migration recorded as applied without having actually run.
func applyMigration(ctx context.Context, db *sql.DB, name, sqlText string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin %s: %w", name, err)
	}
	defer tx.Rollback() // no-op once Commit has succeeded

	if _, err := tx.ExecContext(ctx, sqlText); err != nil {
		return fmt.Errorf("sqlite: apply %s: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (filename, applied_at) VALUES (?, ?)`,
		name, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("sqlite: record %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit %s: %w", name, err)
	}
	return nil
}

func (s *Store) Close() error              { return s.db.Close() }
func (s *Store) Realms() store.RealmRepo   { return &realmRepo{s.db} }
func (s *Store) Clients() store.ClientRepo { return &clientRepo{s.db} }
func (s *Store) Users() store.UserRepo     { return &userRepo{s.db} }
func (s *Store) Roles() store.RoleRepo     { return &roleRepo{s.db} }
func (s *Store) Groups() store.GroupRepo   { return &groupRepo{s.db} }
func (s *Store) Keys() store.KeyRepo       { return &keyRepo{s.db} }

func (s *Store) Sessions() store.SessionRepo { return &sessionRepo{s.db} }

// classify maps driver errors onto the store's sentinels so handlers never
// inspect driver-specific error text.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return store.ErrConflict
	}
	return err
}

func encode(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic("sqlite: encoding a value that must be encodable: " + err.Error())
	}
	return string(b)
}

func decode(s string, v any) error { return json.Unmarshal([]byte(s), v) }

// nonNilStrings keeps a nil slice out of the database as [] rather than null,
// so a scan back yields an empty slice and the representation marshals [].
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// scanner is satisfied by both *sql.Row and *sql.Rows, so single-row getters
// and list methods share one scan implementation per entity.
type scanner interface{ Scan(dest ...any) error }

type realmRepo struct{ db *sql.DB }

// realmColumns is spelled once so the four statements below cannot drift apart
// on the order the scan depends on.
const realmColumns = `id, name, enabled, access_token_lifespan, refresh_token_lifespan, settings`

func (r *realmRepo) Create(ctx context.Context, m *model.Realm) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO realm (`+realmColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
		m.ID, m.Name, m.Enabled, int64(m.AccessTokenLifespan.Seconds()),
		int64(m.RefreshTokenLifespan.Seconds()), string(m.Settings))
	return classify(err)
}

func (r *realmRepo) ByName(ctx context.Context, name string) (*model.Realm, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+realmColumns+` FROM realm WHERE name = ?`, name)
	return scanRealm(row)
}

func (r *realmRepo) List(ctx context.Context) ([]*model.Realm, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+realmColumns+` FROM realm ORDER BY name`)
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

func (r *realmRepo) Update(ctx context.Context, m *model.Realm) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE realm SET name = ?, enabled = ?, access_token_lifespan = ?,
		        refresh_token_lifespan = ?, settings = ?
		 WHERE id = ?`,
		m.Name, m.Enabled, int64(m.AccessTokenLifespan.Seconds()),
		int64(m.RefreshTokenLifespan.Seconds()), string(m.Settings), m.ID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(res)
}

func (r *realmRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM realm WHERE id = ?`, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(res)
}

func scanRealm(row scanner) (*model.Realm, error) {
	m := &model.Realm{}
	var accessSeconds, refreshSeconds int64
	var settings string
	if err := row.Scan(&m.ID, &m.Name, &m.Enabled, &accessSeconds, &refreshSeconds, &settings); err != nil {
		return nil, classify(err)
	}
	m.AccessTokenLifespan = time.Duration(accessSeconds) * time.Second
	m.RefreshTokenLifespan = time.Duration(refreshSeconds) * time.Second
	if settings != "" {
		m.Settings = []byte(settings)
	}
	return m, nil
}

type clientRepo struct{ db *sql.DB }

func (r *clientRepo) Create(ctx context.Context, m *model.Client) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO client (id, realm_id, client_id, name, description, root_url, base_url, enabled, public_client, secret,
		 protocol, client_authenticator_type, surrogate_auth_required, always_display_in_console,
		 bearer_only, consent_required, standard_flow_enabled, implicit_flow_enabled,
		 direct_access_grants_enabled, service_accounts_enabled, frontchannel_logout,
		 full_scope_allowed, not_before, node_re_registration_timeout,
		 redirect_uris, web_origins, default_client_scopes, optional_client_scopes, attributes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.RealmID, m.ClientID, m.Name, m.Description, m.RootURL, m.BaseURL, m.Enabled, m.PublicClient, m.Secret,
		m.Protocol, m.ClientAuthenticatorType, m.SurrogateAuthRequired, m.AlwaysDisplayInConsole,
		m.BearerOnly, m.ConsentRequired, m.StandardFlowEnabled, m.ImplicitFlowEnabled,
		m.DirectAccessGrantsEnabled, m.ServiceAccountsEnabled, m.FrontchannelLogout,
		m.FullScopeAllowed, m.NotBefore, m.NodeReRegistrationTimeout,
		encode(m.RedirectURIs), encode(m.WebOrigins), encode(m.DefaultClientScopes),
		encode(m.OptionalClientScopes), encode(m.Attributes))
	return classify(err)
}

func (r *clientRepo) ByClientID(ctx context.Context, realmID, clientID string) (*model.Client, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, client_id, name, description, root_url, base_url, enabled, public_client, secret,
		 protocol, client_authenticator_type, surrogate_auth_required, always_display_in_console,
		 bearer_only, consent_required, standard_flow_enabled, implicit_flow_enabled,
		 direct_access_grants_enabled, service_accounts_enabled, frontchannel_logout,
		 full_scope_allowed, not_before, node_re_registration_timeout,
		 redirect_uris, web_origins, default_client_scopes, optional_client_scopes, attributes
		 FROM client WHERE realm_id = ? AND client_id = ?`, realmID, clientID)
	return scanClient(row)
}

func (r *clientRepo) ByID(ctx context.Context, realmID, id string) (*model.Client, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, client_id, name, description, root_url, base_url, enabled, public_client, secret,
		 protocol, client_authenticator_type, surrogate_auth_required, always_display_in_console,
		 bearer_only, consent_required, standard_flow_enabled, implicit_flow_enabled,
		 direct_access_grants_enabled, service_accounts_enabled, frontchannel_logout,
		 full_scope_allowed, not_before, node_re_registration_timeout,
		 redirect_uris, web_origins, default_client_scopes, optional_client_scopes, attributes
		 FROM client WHERE realm_id = ? AND id = ?`, realmID, id)
	return scanClient(row)
}

func (r *clientRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.Client, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, realm_id, client_id, name, description, root_url, base_url, enabled, public_client, secret,
		 protocol, client_authenticator_type, surrogate_auth_required, always_display_in_console,
		 bearer_only, consent_required, standard_flow_enabled, implicit_flow_enabled,
		 direct_access_grants_enabled, service_accounts_enabled, frontchannel_logout,
		 full_scope_allowed, not_before, node_re_registration_timeout,
		 redirect_uris, web_origins, default_client_scopes, optional_client_scopes, attributes
		 FROM client WHERE realm_id = ? ORDER BY client_id`, realmID)
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
	res, err := r.db.ExecContext(ctx,
		`UPDATE client SET
			 client_id = ?, name = ?, description = ?, root_url = ?, base_url = ?, enabled = ?, public_client = ?, secret = ?,
			 protocol = ?, client_authenticator_type = ?, surrogate_auth_required = ?,
			 always_display_in_console = ?, bearer_only = ?, consent_required = ?,
			 standard_flow_enabled = ?, implicit_flow_enabled = ?, direct_access_grants_enabled = ?,
			 service_accounts_enabled = ?, frontchannel_logout = ?, full_scope_allowed = ?,
			 not_before = ?, node_re_registration_timeout = ?,
			 redirect_uris = ?, web_origins = ?, default_client_scopes = ?,
			 optional_client_scopes = ?, attributes = ?
			 WHERE realm_id = ? AND id = ?`,
		m.ClientID, m.Name, m.Description, m.RootURL, m.BaseURL, m.Enabled, m.PublicClient, m.Secret,
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
	return affectedOne(res)
}

func (r *clientRepo) Delete(ctx context.Context, realmID, id string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM client WHERE realm_id = ? AND id = ?`, realmID, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(res)
}

func scanClient(row scanner) (*model.Client, error) {
	m := &model.Client{}
	var redirectURIs, webOrigins, defaultScopes, optionalScopes, attributes string
	err := row.Scan(&m.ID, &m.RealmID, &m.ClientID, &m.Name, &m.Description, &m.RootURL, &m.BaseURL,
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
			return nil, fmt.Errorf("sqlite: decode %s: %w", f.name, err)
		}
	}
	return m, nil
}

type userRepo struct{ db *sql.DB }

func (r *userRepo) Create(ctx context.Context, m *model.User) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO user_entity (id, realm_id, username, email, email_verified, enabled,
		 first_name, last_name, created_timestamp, attributes, required_actions, not_before)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.RealmID, m.Username, m.Email, m.EmailVerified, m.Enabled,
		m.FirstName, m.LastName, m.CreatedTimestamp, encode(m.Attributes),
		encode(nonNilStrings(m.RequiredActions)), m.NotBefore)
	return classify(err)
}

func (r *userRepo) ByUsername(ctx context.Context, realmID, username string) (*model.User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, username, email, email_verified, enabled, first_name, last_name,
		 created_timestamp, attributes, required_actions, not_before
		 FROM user_entity WHERE realm_id = ? AND username = ?`, realmID, username)
	return scanUser(row)
}

func (r *userRepo) ByID(ctx context.Context, realmID, id string) (*model.User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, username, email, email_verified, enabled, first_name, last_name,
		 created_timestamp, attributes, required_actions, not_before
		 FROM user_entity WHERE realm_id = ? AND id = ?`, realmID, id)
	return scanUser(row)
}

// ListByRealm orders by username because Keycloak's listing was measured
// sorted rather than in insertion order.
func (r *userRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, realm_id, username, email, email_verified, enabled, first_name, last_name,
		 created_timestamp, attributes, required_actions, not_before
		 FROM user_entity WHERE realm_id = ? ORDER BY username`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	return scanUsers(rows)
}

// scanUsers drains a user query. ListByRealm and RoleRepo.ListUsersWithRole
// select the same row, so the loop lives once.
func scanUsers(rows *sql.Rows) ([]*model.User, error) {
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

func (r *userRepo) Update(ctx context.Context, m *model.User) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE user_entity SET username = ?, email = ?, email_verified = ?, enabled = ?,
		 first_name = ?, last_name = ?, attributes = ?, required_actions = ?, not_before = ?
		 WHERE realm_id = ? AND id = ?`,
		m.Username, m.Email, m.EmailVerified, m.Enabled,
		m.FirstName, m.LastName, encode(m.Attributes),
		encode(nonNilStrings(m.RequiredActions)), m.NotBefore, m.RealmID, m.ID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(res)
}

func (r *userRepo) Delete(ctx context.Context, realmID, id string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM user_entity WHERE realm_id = ? AND id = ?`, realmID, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(res)
}

// SetCredential upserts on (user_id, type) so a password reset can replace an
// existing credential of the same type without a separate delete.
func (r *userRepo) SetCredential(ctx context.Context, m *model.Credential) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO credential (id, user_id, type, created_date, algorithm, hash_iterations,
		 additional_parameters, salt, hash_value, user_label, priority)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (user_id, type) DO UPDATE SET
		 	created_date = excluded.created_date,
		 	algorithm = excluded.algorithm,
		 	hash_iterations = excluded.hash_iterations,
		 	additional_parameters = excluded.additional_parameters,
		 	salt = excluded.salt,
		 	hash_value = excluded.hash_value,
		 	user_label = excluded.user_label`,
		m.ID, m.UserID, m.Type, m.CreatedDate, m.Algorithm, m.HashIterations,
		encode(m.AdditionalParameters), m.Salt, m.HashValue, m.Label, m.Priority)
	return classify(err)
}

func (r *userRepo) CredentialByUser(ctx context.Context, userID, typ string) (*model.Credential, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, user_id, type, created_date, algorithm, hash_iterations, additional_parameters, salt, hash_value, user_label, priority
		 FROM credential WHERE user_id = ? AND type = ? ORDER BY priority, id LIMIT 1`, userID, typ)
	return scanCredential(row)
}

func scanUser(row scanner) (*model.User, error) {
	m := &model.User{}
	var attributes, requiredActions string
	err := row.Scan(&m.ID, &m.RealmID, &m.Username, &m.Email, &m.EmailVerified, &m.Enabled,
		&m.FirstName, &m.LastName, &m.CreatedTimestamp, &attributes, &requiredActions, &m.NotBefore)
	if err != nil {
		return nil, classify(err)
	}
	if err := decode(attributes, &m.Attributes); err != nil {
		return nil, fmt.Errorf("sqlite: decode attributes: %w", err)
	}
	if err := decode(requiredActions, &m.RequiredActions); err != nil {
		return nil, fmt.Errorf("sqlite: decode required_actions: %w", err)
	}
	return m, nil
}

func (r *userRepo) ListCredentials(ctx context.Context, userID string) ([]*model.Credential, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_id, type, created_date, algorithm, hash_iterations, additional_parameters, salt, hash_value, user_label, priority
		 FROM credential WHERE user_id = ? ORDER BY priority, id`, userID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()

	var out []*model.Credential
	for rows.Next() {
		m, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

func (r *userRepo) CredentialByID(ctx context.Context, userID, id string) (*model.Credential, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, user_id, type, created_date, algorithm, hash_iterations, additional_parameters, salt, hash_value, user_label, priority
		 FROM credential WHERE user_id = ? AND id = ?`, userID, id)
	return scanCredential(row)
}

func (r *userRepo) DeleteCredential(ctx context.Context, userID, id string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM credential WHERE user_id = ? AND id = ?`, userID, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(res)
}

func (r *userRepo) UpdateCredential(ctx context.Context, m *model.Credential) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE credential SET user_label = ?, priority = ? WHERE user_id = ? AND id = ?`,
		m.Label, m.Priority, m.UserID, m.ID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(res)
}

func scanCredential(row scanner) (*model.Credential, error) {
	m := &model.Credential{}
	var additionalParameters string
	err := row.Scan(&m.ID, &m.UserID, &m.Type, &m.CreatedDate, &m.Algorithm, &m.HashIterations,
		&additionalParameters, &m.Salt, &m.HashValue, &m.Label, &m.Priority)
	if err != nil {
		return nil, classify(err)
	}
	if err := decode(additionalParameters, &m.AdditionalParameters); err != nil {
		return nil, fmt.Errorf("sqlite: decode additional_parameters: %w", err)
	}
	return m, nil
}

type roleRepo struct{ db *sql.DB }

// Create writes the role row and its attributes in one transaction, so a
// role with attributes never exists half-written.
func (r *roleRepo) Create(ctx context.Context, m *model.Role) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO keycloak_role (id, realm_id, client_id, name, description, composite)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		m.ID, m.RealmID, m.ClientID, m.Name, m.Description, m.Composite); err != nil {
		return classify(err)
	}
	if err := insertRoleAttributes(ctx, tx, m); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *roleRepo) ByName(ctx context.Context, realmID, clientID, name string) (*model.Role, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = ? AND client_id = ? AND name = ?`, realmID, clientID, name)
	m, err := scanRole(row)
	if err != nil {
		return nil, err
	}
	if err := r.loadRoleAttributes(ctx, []*model.Role{m}); err != nil {
		return nil, err
	}
	return m, nil
}

// ListRealmRoles returns realm-level roles, which are stored with an empty
// client_id; client roles are excluded.
func (r *roleRepo) ListRealmRoles(ctx context.Context, realmID string) ([]*model.Role, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = ? AND client_id = '' ORDER BY name`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectRoles(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadRoleAttributes(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *roleRepo) ByID(ctx context.Context, realmID, id string) (*model.Role, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = ? AND id = ?`, realmID, id)
	m, err := scanRole(row)
	if err != nil {
		return nil, err
	}
	if err := r.loadRoleAttributes(ctx, []*model.Role{m}); err != nil {
		return nil, err
	}
	return m, nil
}

// ListClientRoles returns the roles a client owns, the counterpart of
// ListRealmRoles' empty-client_id filter.
func (r *roleRepo) ListClientRoles(ctx context.Context, realmID, clientID string) ([]*model.Role, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = ? AND client_id = ? ORDER BY name`, realmID, clientID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectRoles(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadRoleAttributes(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Update writes the role back whole. Attributes are deleted and re-inserted
// rather than merged, in the same transaction as the row, because PUT on a
// role replaces - see the endpoint above it.
func (r *roleRepo) Update(ctx context.Context, m *model.Role) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE keycloak_role SET name = ?, description = ?, composite = ?
		 WHERE id = ?`,
		m.Name, m.Description, m.Composite, m.ID)
	if err != nil {
		return classify(err)
	}
	if err := affectedOne(res); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_attribute WHERE role_id = ?`, m.ID); err != nil {
		return err
	}
	if err := insertRoleAttributes(ctx, tx, m); err != nil {
		return err
	}
	return tx.Commit()
}

// Delete removes the role and, in the same transaction, clears the composite
// flag on any parent whose last remaining child this was.
//
// The composite_role rows cascade away with the role, but `composite` is a
// column on the *parent*, and the parent is not the row being deleted, so
// nothing else would resync it: the parent would keep answering
// `"composite":true` while its composites listing answered `[]`. The flag is
// derived - true exactly when the role has children, measured in both
// directions - so it cannot be allowed to outlive the last child.
//
// This is in the driver rather than in the three handlers that delete a role
// (deleteRealmRole, deleteClientRole, deleteRoleByID) so that staleness is
// impossible by construction: any future caller of Delete gets it too, without
// having to know the rule exists.
func (r *roleRepo) Delete(ctx context.Context, realmID, id string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`UPDATE keycloak_role SET composite = 0
		 WHERE id IN (SELECT composite FROM composite_role WHERE child_role = ?)
		   AND NOT EXISTS (SELECT 1 FROM composite_role c
		                   WHERE c.composite = keycloak_role.id AND c.child_role <> ?)`,
		id, id); err != nil {
		return classify(err)
	}
	res, err := tx.ExecContext(ctx,
		`DELETE FROM keycloak_role WHERE realm_id = ? AND id = ?`, realmID, id)
	if err != nil {
		return classify(err)
	}
	// Before the commit on purpose: a role that is not there must leave the
	// flags it never touched alone, so the rollback takes the UPDATE with it.
	if err := affectedOne(res); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *roleRepo) AddComposite(ctx context.Context, roleID, childRoleID string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO composite_role (composite, child_role) VALUES (?, ?)`, roleID, childRoleID)
	return classify(err)
}

func (r *roleRepo) ListComposites(ctx context.Context, roleID string) ([]*model.Role, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT r.id, r.realm_id, r.client_id, r.name, r.description, r.composite
		 FROM keycloak_role r
		 JOIN composite_role c ON c.child_role = r.id
		 WHERE c.composite = ? ORDER BY r.name`, roleID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectRoles(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadRoleAttributes(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// RemoveComposite reports no error when the pair is not there: DELETE
// .../composites was measured answering 204 for a role that was never a child.
func (r *roleRepo) RemoveComposite(ctx context.Context, roleID, childRoleID string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM composite_role WHERE composite = ? AND child_role = ?`,
		roleID, childRoleID)
	return classify(err)
}

func (r *roleRepo) AssignToUser(ctx context.Context, userID, roleID string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO user_role_mapping (user_id, role_id) VALUES (?, ?)`, userID, roleID)
	return classify(err)
}

func (r *roleRepo) RemoveFromUser(ctx context.Context, userID, roleID string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM user_role_mapping WHERE user_id = ? AND role_id = ?`, userID, roleID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(res)
}

func (r *roleRepo) ListUserRoles(ctx context.Context, userID string) ([]*model.Role, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT r.id, r.realm_id, r.client_id, r.name, r.description, r.composite
		 FROM keycloak_role r
		 JOIN user_role_mapping m ON m.role_id = r.id
		 WHERE m.user_id = ? ORDER BY r.name`, userID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectRoles(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadRoleAttributes(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListUsersWithRole is the **direct** holders, ordered by username so a
// listing is deterministic. It must not expand composites: measured,
// /roles/create-realm/users is empty even though the administrator reaches
// that role through `admin`.
func (r *roleRepo) ListUsersWithRole(ctx context.Context, realmID, roleID string) ([]*model.User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT u.id, u.realm_id, u.username, u.email, u.email_verified, u.enabled,
		        u.first_name, u.last_name, u.created_timestamp, u.attributes, u.required_actions, u.not_before
		 FROM user_entity u
		 JOIN user_role_mapping m ON m.user_id = u.id
		 WHERE u.realm_id = ? AND m.role_id = ?
		 ORDER BY u.username`, realmID, roleID)
	if err != nil {
		return nil, classify(err)
	}
	return scanUsers(rows)
}

// insertRoleAttributes writes every value of every attribute, ordinal by
// position in the slice, so the order the caller gave them in round-trips.
func insertRoleAttributes(ctx context.Context, tx *sql.Tx, m *model.Role) error {
	for name, values := range m.Attributes {
		for i, v := range values {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO role_attribute (role_id, name, value, ordinal) VALUES (?, ?, ?, ?)`,
				m.ID, name, v, i); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadRoleAttributes fills Attributes on roles already scanned. It runs one
// query for the whole set rather than one per role: ListClientRoles returns 21
// on the admin container alone.
func (r *roleRepo) loadRoleAttributes(ctx context.Context, roles []*model.Role) error {
	if len(roles) == 0 {
		return nil
	}
	byID := make(map[string]*model.Role, len(roles))
	ids := make([]any, 0, len(roles))
	placeholders := make([]string, 0, len(roles))
	for _, role := range roles {
		byID[role.ID] = role
		ids = append(ids, role.ID)
		placeholders = append(placeholders, "?")
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT role_id, name, value FROM role_attribute
		 WHERE role_id IN (`+strings.Join(placeholders, ",")+`)
		 ORDER BY role_id, name, ordinal`, ids...)
	if err != nil {
		return classify(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var roleID, name, value string
		if err := rows.Scan(&roleID, &name, &value); err != nil {
			return err
		}
		role := byID[roleID]
		if role.Attributes == nil {
			role.Attributes = map[string][]string{}
		}
		role.Attributes[name] = append(role.Attributes[name], value)
	}
	return rows.Err()
}

// collectRoles drains a role query. Every role listing scans the same six
// columns, so the loop lives once.
func collectRoles(rows *sql.Rows) ([]*model.Role, error) {
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

type keyRepo struct{ db *sql.DB }

func (r *keyRepo) Create(ctx context.Context, m *model.RealmKey) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO realm_key (id, realm_id, algorithm, key_use, private_key, certificate, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.RealmID, m.Algorithm, m.Use, m.PrivateKey, m.Certificate, m.CreatedAt)
	return classify(err)
}

func (r *keyRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.RealmKey, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, realm_id, algorithm, key_use, private_key, certificate, created_at
		 FROM realm_key WHERE realm_id = ? ORDER BY algorithm`, realmID)
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

type sessionRepo struct{ db *sql.DB }

func (r *sessionRepo) CreateUserSession(ctx context.Context, m *model.UserSession) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO user_session (id, realm_id, user_id, username, started_at, last_refresh, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.RealmID, m.UserID, m.Username, m.StartedAt, m.LastRefresh, m.ExpiresAt)
	return classify(err)
}

func (r *sessionRepo) UserSessionByID(ctx context.Context, realmID, id string) (*model.UserSession, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, user_id, username, started_at, last_refresh, expires_at
		 FROM user_session WHERE realm_id = ? AND id = ?`, realmID, id)
	return scanUserSession(row)
}

// TouchUserSession records a refresh. It reports ErrNotFound when it matches
// no row: the driver treats an update affecting nothing as success, so without
// this check a refresh against a revoked session would look like it worked.
func (r *sessionRepo) TouchUserSession(ctx context.Context, id string, lastRefresh int64) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE user_session SET last_refresh = ? WHERE id = ?`, lastRefresh, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(res)
}

// DeleteUserSession removes the session and, through the schema's cascade, the
// client sessions hanging off it.
func (r *sessionRepo) DeleteUserSession(ctx context.Context, realmID, id string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM user_session WHERE realm_id = ? AND id = ?`, realmID, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(res)
}

func (r *sessionRepo) DeleteUserSessions(ctx context.Context, realmID, userID string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM user_session WHERE realm_id = ? AND user_id = ?`, realmID, userID)
	return classify(err)
}

func (r *sessionRepo) CreateClientSession(ctx context.Context, m *model.ClientSession) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO client_session (id, user_session_id, client_id, scope, started_at)
		 VALUES (?, ?, ?, ?, ?)`,
		m.ID, m.UserSessionID, m.ClientID, m.Scope, m.StartedAt)
	return classify(err)
}

func (r *sessionRepo) ClientSession(ctx context.Context, userSessionID, clientID string) (*model.ClientSession, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, user_session_id, client_id, scope, started_at
		 FROM client_session WHERE user_session_id = ? AND client_id = ?`, userSessionID, clientID)
	return scanClientSession(row)
}

// affectedOne turns "this statement changed nothing" into ErrNotFound.
func affectedOne(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
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

type groupRepo struct{ db *sql.DB }

// Create writes the group row and its attributes in one transaction, so a
// group with attributes never exists half-written - roleRepo.Create's shape,
// for the same reason.
func (r *groupRepo) Create(ctx context.Context, m *model.Group) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO keycloak_group (id, realm_id, parent_id, name) VALUES (?, ?, ?, ?)`,
		m.ID, m.RealmID, m.ParentID, m.Name); err != nil {
		return classify(err)
	}
	if err := insertGroupAttributes(ctx, tx, m); err != nil {
		return classify(err)
	}
	return tx.Commit()
}

func (r *groupRepo) ByID(ctx context.Context, realmID, id string) (*model.Group, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, parent_id, name FROM keycloak_group
		 WHERE realm_id = ? AND id = ?`, realmID, id)
	m, err := scanGroup(row)
	if err != nil {
		return nil, err
	}
	if err := r.loadGroupAttributes(ctx, []*model.Group{m}); err != nil {
		return nil, err
	}
	return m, nil
}

// Update writes name and attributes back. parent_id is not in the statement:
// nothing in the admin API reparents a group, so a repo that could would be
// offering a move nobody has measured.
func (r *groupRepo) Update(ctx context.Context, m *model.Group) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx,
		`UPDATE keycloak_group SET name = ? WHERE realm_id = ? AND id = ?`,
		m.Name, m.RealmID, m.ID)
	if err != nil {
		return classify(err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return store.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM group_attribute WHERE group_id = ?`, m.ID); err != nil {
		return classify(err)
	}
	if err := insertGroupAttributes(ctx, tx, m); err != nil {
		return classify(err)
	}
	return tx.Commit()
}

// Delete removes the group and its whole subtree.
//
// **The subtree is walked here rather than cascaded by the schema.** parent_id
// is ” for a top-level group, following keycloak_role.client_id, and a foreign
// key cannot point at ”  - so the column carries no REFERENCES clause and
// there is nothing for the database to cascade. group_attribute and
// group_membership do cascade, because their keys are real; only the
// parent link is walked.
//
// This was a real defect for one commit: the migration's comment claimed a
// cascade the column never had, and the driver suite caught a child outliving
// its parent.
func (r *groupRepo) Delete(ctx context.Context, realmID, id string) error {
	if _, err := r.ByID(ctx, realmID, id); err != nil {
		return err
	}
	ids, err := r.subtree(ctx, realmID, id)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, gid := range ids {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM keycloak_group WHERE realm_id = ? AND id = ?`, realmID, gid); err != nil {
			return classify(err)
		}
	}
	return tx.Commit()
}

// subtree is the group and every group under it, deepest last, so deleting in
// order never orphans a row a later step still needs to find.
func (r *groupRepo) subtree(ctx context.Context, realmID, id string) ([]string, error) {
	out := []string{id}
	for i := 0; i < len(out); i++ {
		kids, err := r.ListChildren(ctx, realmID, out[i])
		if err != nil {
			return nil, err
		}
		for _, k := range kids {
			out = append(out, k.ID)
		}
	}
	// Deepest last on the way in, so reverse to delete leaves first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// ListTopLevel is what GET /groups answers: the groups with no parent.
// Measured top-level only, while the count beside it counts the whole tree.
func (r *groupRepo) ListTopLevel(ctx context.Context, realmID string) ([]*model.Group, error) {
	return r.list(ctx, `WHERE realm_id = ? AND parent_id = '' ORDER BY name`, realmID)
}

func (r *groupRepo) ListChildren(ctx context.Context, realmID, parentID string) ([]*model.Group, error) {
	return r.list(ctx, `WHERE realm_id = ? AND parent_id = ? ORDER BY name`, realmID, parentID)
}

func (r *groupRepo) list(ctx context.Context, where string, args ...any) ([]*model.Group, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, realm_id, parent_id, name FROM keycloak_group `+where, args...)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectGroups(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadGroupAttributes(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListAll is every group at any depth. The count and the search both need the
// whole tree, so they share this rather than a COUNT that could disagree with a
// walk.
func (r *groupRepo) ListAll(ctx context.Context, realmID string) ([]*model.Group, error) {
	return r.list(ctx, `WHERE realm_id = ? ORDER BY name`, realmID)
}

// Ancestry walks parent_id upwards and returns the chain nearest last, so the
// caller reads it as a path left to right. It is a loop rather than a recursive
// CTE because the two drivers would spell the CTE differently and the depth is
// the tree's, not the realm's.
func (r *groupRepo) Ancestry(ctx context.Context, realmID, id string) ([]*model.Group, error) {
	var chain []*model.Group
	for id != "" {
		g, err := r.ByID(ctx, realmID, id)
		if err != nil {
			return nil, err
		}
		chain = append([]*model.Group{g}, chain...)
		id = g.ParentID
	}
	return chain, nil
}

// Members are the users assigned to this group **directly**. A user in a child
// was measured not being a member of its parent, so this does not walk down.
func (r *groupRepo) Members(ctx context.Context, realmID, groupID string) ([]*model.User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT u.id, u.realm_id, u.username, u.email, u.email_verified, u.enabled,
		        u.first_name, u.last_name, u.created_timestamp, u.attributes, u.required_actions, u.not_before
		 FROM user_entity u
		 JOIN group_membership m ON m.user_id = u.id
		 WHERE u.realm_id = ? AND m.group_id = ?
		 ORDER BY u.username`, realmID, groupID)
	if err != nil {
		return nil, classify(err)
	}
	return scanUsers(rows)
}

// AddMember is idempotent: PUT .../groups/{id} was measured answering 204 for a
// membership the user already had.
func (r *groupRepo) AddMember(ctx context.Context, groupID, userID string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO group_membership (group_id, user_id) VALUES (?, ?)
		 ON CONFLICT DO NOTHING`, groupID, userID)
	return classify(err)
}

// RemoveMember reports no error for a membership that is not there, the way
// RoleRepo.RemoveComposite does for the same measured reason.
func (r *groupRepo) RemoveMember(ctx context.Context, groupID, userID string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM group_membership WHERE group_id = ? AND user_id = ?`, groupID, userID)
	return classify(err)
}

func (r *groupRepo) ListUserGroups(ctx context.Context, realmID, userID string) ([]*model.Group, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT g.id, g.realm_id, g.parent_id, g.name FROM keycloak_group g
		 JOIN group_membership m ON m.group_id = g.id
		 WHERE g.realm_id = ? AND m.user_id = ? ORDER BY g.name`, realmID, userID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectGroups(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadGroupAttributes(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *groupRepo) ListDefaultGroups(ctx context.Context, realmID string) ([]*model.Group, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT g.id, g.realm_id, g.parent_id, g.name FROM keycloak_group g
		 JOIN realm_default_group d ON d.group_id = g.id
		 WHERE d.realm_id = ? ORDER BY g.name`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectGroups(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadGroupAttributes(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *groupRepo) AddDefaultGroup(ctx context.Context, realmID, groupID string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO realm_default_group (realm_id, group_id) VALUES (?, ?)
		 ON CONFLICT DO NOTHING`, realmID, groupID)
	return classify(err)
}

func (r *groupRepo) RemoveDefaultGroup(ctx context.Context, realmID, groupID string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM realm_default_group WHERE realm_id = ? AND group_id = ?`, realmID, groupID)
	return classify(err)
}

func insertGroupAttributes(ctx context.Context, tx *sql.Tx, m *model.Group) error {
	for name, values := range m.Attributes {
		for i, v := range values {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO group_attribute (group_id, name, value, ordinal) VALUES (?, ?, ?, ?)`,
				m.ID, name, v, i); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadGroupAttributes fills Attributes on groups already scanned, one query for
// the whole set - loadRoleAttributes' shape.
func (r *groupRepo) loadGroupAttributes(ctx context.Context, groups []*model.Group) error {
	if len(groups) == 0 {
		return nil
	}
	byID := make(map[string]*model.Group, len(groups))
	ids := make([]any, 0, len(groups))
	placeholders := make([]string, 0, len(groups))
	for _, g := range groups {
		byID[g.ID] = g
		ids = append(ids, g.ID)
		placeholders = append(placeholders, "?")
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT group_id, name, value FROM group_attribute
		 WHERE group_id IN (`+strings.Join(placeholders, ",")+`)
		 ORDER BY group_id, name, ordinal`, ids...)
	if err != nil {
		return classify(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var groupID, name, value string
		if err := rows.Scan(&groupID, &name, &value); err != nil {
			return err
		}
		g := byID[groupID]
		if g.Attributes == nil {
			g.Attributes = map[string][]string{}
		}
		g.Attributes[name] = append(g.Attributes[name], value)
	}
	return classify(rows.Err())
}

func collectGroups(rows *sql.Rows) ([]*model.Group, error) {
	defer func() { _ = rows.Close() }()
	var out []*model.Group
	for rows.Next() {
		m, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

func scanGroup(row scanner) (*model.Group, error) {
	m := &model.Group{}
	if err := row.Scan(&m.ID, &m.RealmID, &m.ParentID, &m.Name); err != nil {
		return nil, classify(err)
	}
	return m, nil
}

// AssignToGroup is AssignToUser's mirror. The mapping write is measured
// idempotent on a group holder as on a user one, so a repeat is not a conflict.
func (r *roleRepo) AssignToGroup(ctx context.Context, groupID, roleID string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO group_role_mapping (group_id, role_id) VALUES (?, ?)
		 ON CONFLICT DO NOTHING`, groupID, roleID)
	return classify(err)
}

// RemoveFromGroup reports no error for a mapping that is not there, the way
// RemoveFromUser's route was measured answering 204 for one never held.
func (r *roleRepo) RemoveFromGroup(ctx context.Context, groupID, roleID string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM group_role_mapping WHERE group_id = ? AND role_id = ?`, groupID, roleID)
	return classify(err)
}

func (r *roleRepo) ListGroupRoles(ctx context.Context, groupID string) ([]*model.Role, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT r.id, r.realm_id, r.client_id, r.name, r.description, r.composite
		 FROM keycloak_role r
		 JOIN group_role_mapping m ON m.role_id = r.id
		 WHERE m.group_id = ? ORDER BY r.name`, groupID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectRoles(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadRoleAttributes(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

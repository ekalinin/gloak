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

// scanner is satisfied by both *sql.Row and *sql.Rows, so single-row getters
// and list methods share one scan implementation per entity.
type scanner interface{ Scan(dest ...any) error }

type realmRepo struct{ db *sql.DB }

func (r *realmRepo) Create(ctx context.Context, m *model.Realm) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO realm (id, name, enabled, access_token_lifespan, refresh_token_lifespan)
		 VALUES (?, ?, ?, ?, ?)`,
		m.ID, m.Name, m.Enabled, int64(m.AccessTokenLifespan.Seconds()), int64(m.RefreshTokenLifespan.Seconds()))
	return classify(err)
}

func (r *realmRepo) ByName(ctx context.Context, name string) (*model.Realm, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, name, enabled, access_token_lifespan, refresh_token_lifespan
		 FROM realm WHERE name = ?`, name)
	return scanRealm(row)
}

func (r *realmRepo) List(ctx context.Context) ([]*model.Realm, error) {
	rows, err := r.db.QueryContext(ctx,
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

type clientRepo struct{ db *sql.DB }

func (r *clientRepo) Create(ctx context.Context, m *model.Client) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO client (id, realm_id, client_id, name, enabled, public_client, secret,
		 standard_flow_enabled, direct_access_grants_enabled, service_accounts_enabled,
		 redirect_uris, web_origins, attributes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.RealmID, m.ClientID, m.Name, m.Enabled, m.PublicClient, m.Secret,
		m.StandardFlowEnabled, m.DirectAccessGrantsEnabled, m.ServiceAccountsEnabled,
		encode(m.RedirectURIs), encode(m.WebOrigins), encode(m.Attributes))
	return classify(err)
}

func (r *clientRepo) ByClientID(ctx context.Context, realmID, clientID string) (*model.Client, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, client_id, name, enabled, public_client, secret,
		 standard_flow_enabled, direct_access_grants_enabled, service_accounts_enabled,
		 redirect_uris, web_origins, attributes
		 FROM client WHERE realm_id = ? AND client_id = ?`, realmID, clientID)
	return scanClient(row)
}

func (r *clientRepo) ByID(ctx context.Context, realmID, id string) (*model.Client, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, client_id, name, enabled, public_client, secret,
		 standard_flow_enabled, direct_access_grants_enabled, service_accounts_enabled,
		 redirect_uris, web_origins, attributes
		 FROM client WHERE realm_id = ? AND id = ?`, realmID, id)
	return scanClient(row)
}

func (r *clientRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.Client, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, realm_id, client_id, name, enabled, public_client, secret,
		 standard_flow_enabled, direct_access_grants_enabled, service_accounts_enabled,
		 redirect_uris, web_origins, attributes
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
		return nil, fmt.Errorf("sqlite: decode redirect_uris: %w", err)
	}
	if err := decode(webOrigins, &m.WebOrigins); err != nil {
		return nil, fmt.Errorf("sqlite: decode web_origins: %w", err)
	}
	if err := decode(attributes, &m.Attributes); err != nil {
		return nil, fmt.Errorf("sqlite: decode attributes: %w", err)
	}
	return m, nil
}

type userRepo struct{ db *sql.DB }

func (r *userRepo) Create(ctx context.Context, m *model.User) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO user_entity (id, realm_id, username, email, email_verified, enabled,
		 first_name, last_name, created_timestamp, attributes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.RealmID, m.Username, m.Email, m.EmailVerified, m.Enabled,
		m.FirstName, m.LastName, m.CreatedTimestamp, encode(m.Attributes))
	return classify(err)
}

func (r *userRepo) ByUsername(ctx context.Context, realmID, username string) (*model.User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, username, email, email_verified, enabled, first_name, last_name,
		 created_timestamp, attributes
		 FROM user_entity WHERE realm_id = ? AND username = ?`, realmID, username)
	return scanUser(row)
}

func (r *userRepo) ByID(ctx context.Context, realmID, id string) (*model.User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, username, email, email_verified, enabled, first_name, last_name,
		 created_timestamp, attributes
		 FROM user_entity WHERE realm_id = ? AND id = ?`, realmID, id)
	return scanUser(row)
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
		 additional_parameters, salt, hash_value)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
	row := r.db.QueryRowContext(ctx,
		`SELECT id, user_id, type, created_date, algorithm, hash_iterations, additional_parameters, salt, hash_value
		 FROM credential WHERE user_id = ? AND type = ?`, userID, typ)
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
		return nil, fmt.Errorf("sqlite: decode attributes: %w", err)
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
		return nil, fmt.Errorf("sqlite: decode additional_parameters: %w", err)
	}
	return m, nil
}

type roleRepo struct{ db *sql.DB }

func (r *roleRepo) Create(ctx context.Context, m *model.Role) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO keycloak_role (id, realm_id, client_id, name, description, composite)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		m.ID, m.RealmID, m.ClientID, m.Name, m.Description, m.Composite)
	return classify(err)
}

func (r *roleRepo) ByName(ctx context.Context, realmID, clientID, name string) (*model.Role, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = ? AND client_id = ? AND name = ?`, realmID, clientID, name)
	return scanRole(row)
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
	row := r.db.QueryRowContext(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = ? AND id = ?`, realmID, id)
	return scanRole(row)
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
	return collectRoles(rows)
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
	return collectRoles(rows)
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
	return collectRoles(rows)
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

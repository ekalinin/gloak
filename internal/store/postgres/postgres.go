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
	"strings"
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

func (s *Store) ClientScopes() store.ClientScopeRepo { return &clientScopeRepo{s.pool} }

func (s *Store) Users() store.UserRepo   { return &userRepo{s.pool} }
func (s *Store) Roles() store.RoleRepo   { return &roleRepo{s.pool} }
func (s *Store) Groups() store.GroupRepo { return &groupRepo{s.pool} }
func (s *Store) Keys() store.KeyRepo     { return &keyRepo{s.pool} }

func (s *Store) Sessions() store.SessionRepo { return &sessionRepo{s.pool} }

func (s *Store) RequiredActions() store.RequiredActionRepo {
	return &requiredActionRepo{s.pool}
}

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

// nonNilStrings keeps a nil slice out of the database as [] rather than null,
// so a scan back yields an empty slice and the representation marshals [].
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// boolToInt writes a flag as an integer in both drivers rather than as each
// dialect's own boolean. The two membership tables carry one, and storing it
// the same way in both is what keeps the migration files identical.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// scanner is satisfied by both pgx.Row and pgx.Rows, so single-row getters
// and list methods share one scan implementation per entity.
type scanner interface{ Scan(dest ...any) error }

type realmRepo struct{ pool *pgxpool.Pool }

// realmColumns is spelled once so the four statements below cannot drift apart
// on the order the scan depends on.
const realmColumns = `id, name, enabled, access_token_lifespan, refresh_token_lifespan, settings`

func (r *realmRepo) Create(ctx context.Context, m *model.Realm) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO realm (`+realmColumns+`) VALUES ($1, $2, $3, $4, $5, $6)`,
		m.ID, m.Name, m.Enabled, int64(m.AccessTokenLifespan.Seconds()),
		int64(m.RefreshTokenLifespan.Seconds()), string(m.Settings))
	return classify(err)
}

func (r *realmRepo) ByName(ctx context.Context, name string) (*model.Realm, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+realmColumns+` FROM realm WHERE name = $1`, name)
	return scanRealm(row)
}

func (r *realmRepo) List(ctx context.Context) ([]*model.Realm, error) {
	rows, err := r.pool.Query(ctx,
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
	tag, err := r.pool.Exec(ctx,
		`UPDATE realm SET name = $1, enabled = $2, access_token_lifespan = $3,
		        refresh_token_lifespan = $4, settings = $5
		 WHERE id = $6`,
		m.Name, m.Enabled, int64(m.AccessTokenLifespan.Seconds()),
		int64(m.RefreshTokenLifespan.Seconds()), string(m.Settings), m.ID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

func (r *realmRepo) Delete(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM realm WHERE id = $1`, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
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

type clientRepo struct{ pool *pgxpool.Pool }

func (r *clientRepo) Create(ctx context.Context, m *model.Client) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO client (id, realm_id, client_id, name, description, root_url, base_url, enabled, public_client, secret,
		 protocol, client_authenticator_type, surrogate_auth_required, always_display_in_console,
		 bearer_only, consent_required, standard_flow_enabled, implicit_flow_enabled,
		 direct_access_grants_enabled, service_accounts_enabled, frontchannel_logout,
		 full_scope_allowed, not_before, node_re_registration_timeout,
		 redirect_uris, web_origins, attributes, protocol_mappers)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)`,
		m.ID, m.RealmID, m.ClientID, m.Name, m.Description, m.RootURL, m.BaseURL, m.Enabled, m.PublicClient, m.Secret,
		m.Protocol, m.ClientAuthenticatorType, m.SurrogateAuthRequired, m.AlwaysDisplayInConsole,
		m.BearerOnly, m.ConsentRequired, m.StandardFlowEnabled, m.ImplicitFlowEnabled,
		m.DirectAccessGrantsEnabled, m.ServiceAccountsEnabled, m.FrontchannelLogout,
		m.FullScopeAllowed, m.NotBefore, m.NodeReRegistrationTimeout,
		encode(m.RedirectURIs), encode(m.WebOrigins), encode(m.Attributes),
		encode(m.ProtocolMappers))
	if err != nil {
		return classify(err)
	}
	return r.attachClientScopes(ctx, m)
}

// attachClientScopes turns the two name lists a caller set on the model into
// rows in client_client_scope, which is where a client's scopes actually live.
//
// It runs on Create and **not** on Update, measured: PUT /clients/{uuid} with
// `defaultClientScopes:["email"]` answered 204 and changed nothing, and so did
// the same PUT with `[]`. The two lists are write-once at create; afterwards
// only the four dedicated routes move them.
//
// A name the realm does not have is skipped rather than reported, measured: a
// client created naming "nosuchscope" answered 201 and read back with an empty
// list.
func (r *clientRepo) attachClientScopes(ctx context.Context, m *model.Client) error {
	add := func(names []string, defaultScope bool) error {
		for _, name := range names {
			if _, err := r.pool.Exec(ctx,
				`INSERT INTO client_client_scope (client_id, client_scope_id, default_scope)
				 SELECT $1, id, $2 FROM client_scope WHERE realm_id = $3 AND name = $4
				 ON CONFLICT DO NOTHING`,
				m.ID, boolToInt(defaultScope), m.RealmID, name); err != nil {
				return classify(err)
			}
		}
		return nil
	}
	if err := add(m.DefaultClientScopes, true); err != nil {
		return err
	}
	return add(m.OptionalClientScopes, false)
}

func (r *clientRepo) ByClientID(ctx context.Context, realmID, clientID string) (*model.Client, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, client_id, name, description, root_url, base_url, enabled, public_client, secret,
		 protocol, client_authenticator_type, surrogate_auth_required, always_display_in_console,
		 bearer_only, consent_required, standard_flow_enabled, implicit_flow_enabled,
		 direct_access_grants_enabled, service_accounts_enabled, frontchannel_logout,
		 full_scope_allowed, not_before, node_re_registration_timeout,
		 redirect_uris, web_origins, attributes, protocol_mappers
		 FROM client WHERE realm_id = $1 AND client_id = $2`, realmID, clientID)
	return r.scanWithScopes(ctx, row)
}

func (r *clientRepo) ByID(ctx context.Context, realmID, id string) (*model.Client, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, client_id, name, description, root_url, base_url, enabled, public_client, secret,
		 protocol, client_authenticator_type, surrogate_auth_required, always_display_in_console,
		 bearer_only, consent_required, standard_flow_enabled, implicit_flow_enabled,
		 direct_access_grants_enabled, service_accounts_enabled, frontchannel_logout,
		 full_scope_allowed, not_before, node_re_registration_timeout,
		 redirect_uris, web_origins, attributes, protocol_mappers
		 FROM client WHERE realm_id = $1 AND id = $2`, realmID, id)
	return r.scanWithScopes(ctx, row)
}

func (r *clientRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.Client, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, realm_id, client_id, name, description, root_url, base_url, enabled, public_client, secret,
		 protocol, client_authenticator_type, surrogate_auth_required, always_display_in_console,
		 bearer_only, consent_required, standard_flow_enabled, implicit_flow_enabled,
		 direct_access_grants_enabled, service_accounts_enabled, frontchannel_logout,
		 full_scope_allowed, not_before, node_re_registration_timeout,
		 redirect_uris, web_origins, attributes, protocol_mappers
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
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, classify(err)
	}
	for _, m := range out {
		if err := r.loadClientScopeNames(ctx, m); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// scanWithScopes reads one client and fills its two client-scope name lists.
//
// The names are **derived**, not stored. The client row carried them as two
// JSON columns until 0014, and a client's attachment has to survive a client
// scope being renamed - measured: renaming a scope changed the name in every
// client's list and kept the attachment - which a name cannot do. So
// client_client_scope holds ids and is the only truth, and model.Client keeps
// carrying names because that is what the representation serialises and what
// internal/oidc validates a requested scope against.
func (r *clientRepo) scanWithScopes(ctx context.Context, row scanner) (*model.Client, error) {
	m, err := scanClient(row)
	if err != nil {
		return nil, err
	}
	if err := r.loadClientScopeNames(ctx, m); err != nil {
		return nil, err
	}
	return m, nil
}

func (r *clientRepo) loadClientScopeNames(ctx context.Context, m *model.Client) error {
	rows, err := r.pool.Query(ctx,
		`SELECT s.name, c.default_scope FROM client_scope s
		 JOIN client_client_scope c ON c.client_scope_id = s.id
		 WHERE c.client_id = $1 ORDER BY s.name`, m.ID)
	if err != nil {
		return classify(err)
	}
	defer rows.Close()

	m.DefaultClientScopes = []string{}
	m.OptionalClientScopes = []string{}
	for rows.Next() {
		var name string
		var defaultScope int
		if err := rows.Scan(&name, &defaultScope); err != nil {
			return classify(err)
		}
		if defaultScope == 1 {
			m.DefaultClientScopes = append(m.DefaultClientScopes, name)
		} else {
			m.OptionalClientScopes = append(m.OptionalClientScopes, name)
		}
	}
	return classify(rows.Err())
}

// Update replaces every mutable column. The admin API's PUT carries a whole
// representation, and merge semantics are applied above this layer.
func (r *clientRepo) Update(ctx context.Context, m *model.Client) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE client SET
			 client_id = $1, name = $2, description = $3, root_url = $4, base_url = $5, enabled = $6,
			 public_client = $7,
			 secret = $8, protocol = $9, client_authenticator_type = $10, surrogate_auth_required = $11,
			 always_display_in_console = $12, bearer_only = $13, consent_required = $14,
			 standard_flow_enabled = $15, implicit_flow_enabled = $16, direct_access_grants_enabled = $17,
			 service_accounts_enabled = $18, frontchannel_logout = $19, full_scope_allowed = $20,
			 not_before = $21, node_re_registration_timeout = $22,
			 redirect_uris = $23, web_origins = $24, attributes = $25, protocol_mappers = $26
			 WHERE realm_id = $27 AND id = $28`,
		m.ClientID, m.Name, m.Description, m.RootURL, m.BaseURL, m.Enabled, m.PublicClient, m.Secret,
		m.Protocol, m.ClientAuthenticatorType, m.SurrogateAuthRequired,
		m.AlwaysDisplayInConsole, m.BearerOnly, m.ConsentRequired,
		m.StandardFlowEnabled, m.ImplicitFlowEnabled, m.DirectAccessGrantsEnabled,
		m.ServiceAccountsEnabled, m.FrontchannelLogout, m.FullScopeAllowed,
		m.NotBefore, m.NodeReRegistrationTimeout,
		encode(m.RedirectURIs), encode(m.WebOrigins), encode(m.Attributes),
		encode(m.ProtocolMappers),
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

// ProtocolMapperOwner scans every client on the server. There is no WHERE on
// the realm because the uniqueness is server-wide, and none on the mapper id
// because the mappers are a JSON column rather than a table - the only thing a
// unique index could sit on here is a row that does not exist.
//
// The scan is store.HoldsProtocolMapper so that the SQLite driver beside this
// one cannot read the same bytes differently.
func (r *clientRepo) ProtocolMapperOwner(ctx context.Context, mapperID string) (string, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, protocol_mappers FROM client`)
	if err != nil {
		return "", classify(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, mappers string
		if err := rows.Scan(&id, &mappers); err != nil {
			return "", classify(err)
		}
		if store.HoldsProtocolMapper(mappers, mapperID) {
			return id, nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", classify(err)
	}
	return "", store.ErrNotFound
}

func scanClient(row scanner) (*model.Client, error) {
	m := &model.Client{}
	var redirectURIs, webOrigins, attributes, protocolMappers string
	err := row.Scan(&m.ID, &m.RealmID, &m.ClientID, &m.Name, &m.Description, &m.RootURL, &m.BaseURL,
		&m.Enabled, &m.PublicClient, &m.Secret,
		&m.Protocol, &m.ClientAuthenticatorType, &m.SurrogateAuthRequired, &m.AlwaysDisplayInConsole,
		&m.BearerOnly, &m.ConsentRequired, &m.StandardFlowEnabled, &m.ImplicitFlowEnabled,
		&m.DirectAccessGrantsEnabled, &m.ServiceAccountsEnabled, &m.FrontchannelLogout,
		&m.FullScopeAllowed, &m.NotBefore, &m.NodeReRegistrationTimeout,
		&redirectURIs, &webOrigins, &attributes, &protocolMappers)
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
		{attributes, &m.Attributes, "attributes"},
		{protocolMappers, &m.ProtocolMappers, "protocol_mappers"},
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
		 first_name, last_name, created_timestamp, attributes, required_actions, not_before)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		m.ID, m.RealmID, m.Username, m.Email, m.EmailVerified, m.Enabled,
		m.FirstName, m.LastName, m.CreatedTimestamp, encode(m.Attributes),
		encode(nonNilStrings(m.RequiredActions)), m.NotBefore)
	return classify(err)
}

func (r *userRepo) ByUsername(ctx context.Context, realmID, username string) (*model.User, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, username, email, email_verified, enabled, first_name, last_name,
		 created_timestamp, attributes, required_actions, not_before
		 FROM user_entity WHERE realm_id = $1 AND username = $2`, realmID, username)
	return scanUser(row)
}

func (r *userRepo) ByID(ctx context.Context, realmID, id string) (*model.User, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, username, email, email_verified, enabled, first_name, last_name,
		 created_timestamp, attributes, required_actions, not_before
		 FROM user_entity WHERE realm_id = $1 AND id = $2`, realmID, id)
	return scanUser(row)
}

// ListByRealm orders by username because Keycloak's listing was measured
// sorted rather than in insertion order.
func (r *userRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.User, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, realm_id, username, email, email_verified, enabled, first_name, last_name,
		 created_timestamp, attributes, required_actions, not_before
		 FROM user_entity WHERE realm_id = $1 ORDER BY username`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	return scanUsers(rows)
}

// scanUsers drains a user query. ListByRealm and RoleRepo.ListUsersWithRole
// select the same row, so the loop lives once.
func scanUsers(rows pgx.Rows) ([]*model.User, error) {
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
	tag, err := r.pool.Exec(ctx,
		`UPDATE user_entity SET username = $1, email = $2, email_verified = $3, enabled = $4,
		 first_name = $5, last_name = $6, attributes = $7, required_actions = $8, not_before = $9
		 WHERE realm_id = $10 AND id = $11`,
		m.Username, m.Email, m.EmailVerified, m.Enabled,
		m.FirstName, m.LastName, encode(m.Attributes),
		encode(nonNilStrings(m.RequiredActions)), m.NotBefore, m.RealmID, m.ID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
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
		 additional_parameters, salt, hash_value, user_label, priority)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
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
	row := r.pool.QueryRow(ctx,
		`SELECT id, user_id, type, created_date, algorithm, hash_iterations, additional_parameters, salt, hash_value, user_label, priority
		 FROM credential WHERE user_id = $1 AND type = $2 ORDER BY priority, id LIMIT 1`, userID, typ)
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
		return nil, fmt.Errorf("postgres: decode attributes: %w", err)
	}
	if err := decode(requiredActions, &m.RequiredActions); err != nil {
		return nil, fmt.Errorf("postgres: decode required_actions: %w", err)
	}
	return m, nil
}

func (r *userRepo) ListCredentials(ctx context.Context, userID string) ([]*model.Credential, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, type, created_date, algorithm, hash_iterations, additional_parameters, salt, hash_value, user_label, priority
		 FROM credential WHERE user_id = $1 ORDER BY priority, id`, userID)
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
	row := r.pool.QueryRow(ctx,
		`SELECT id, user_id, type, created_date, algorithm, hash_iterations, additional_parameters, salt, hash_value, user_label, priority
		 FROM credential WHERE user_id = $1 AND id = $2`, userID, id)
	return scanCredential(row)
}

func (r *userRepo) DeleteCredential(ctx context.Context, userID, id string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM credential WHERE user_id = $1 AND id = $2`, userID, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

func (r *userRepo) UpdateCredential(ctx context.Context, m *model.Credential) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE credential SET user_label = $1, priority = $2 WHERE user_id = $3 AND id = $4`,
		m.Label, m.Priority, m.UserID, m.ID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
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
		return nil, fmt.Errorf("postgres: decode additional_parameters: %w", err)
	}
	return m, nil
}

type roleRepo struct{ pool *pgxpool.Pool }

// Create writes the role row and its attributes in one transaction, so a
// role with attributes never exists half-written.
func (r *roleRepo) Create(ctx context.Context, m *model.Role) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO keycloak_role (id, realm_id, client_id, name, description, composite)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		m.ID, m.RealmID, m.ClientID, m.Name, m.Description, m.Composite); err != nil {
		return classify(err)
	}
	if err := insertRoleAttributes(ctx, tx, m); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

func (r *roleRepo) ByName(ctx context.Context, realmID, clientID, name string) (*model.Role, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = $1 AND client_id = $2 AND name = $3`, realmID, clientID, name)
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
	rows, err := r.pool.Query(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = $1 AND client_id = '' ORDER BY name`, realmID)
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
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = $1 AND id = $2`, realmID, id)
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
	rows, err := r.pool.Query(ctx,
		`SELECT id, realm_id, client_id, name, description, composite
		 FROM keycloak_role WHERE realm_id = $1 AND client_id = $2 ORDER BY name`, realmID, clientID)
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
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE keycloak_role SET name = $1, description = $2, composite = $3
		 WHERE id = $4`,
		m.Name, m.Description, m.Composite, m.ID)
	if err != nil {
		return classify(err)
	}
	if err := affectedOne(tag.RowsAffected()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM role_attribute WHERE role_id = $1`, m.ID); err != nil {
		return classify(err)
	}
	if err := insertRoleAttributes(ctx, tx, m); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

// Delete removes the role and, in the same transaction, clears the composite
// flag on any parent whose last remaining child this was. See the sqlite
// driver's Delete for why this belongs here rather than in the handlers.
func (r *roleRepo) Delete(ctx context.Context, realmID, id string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`UPDATE keycloak_role SET composite = FALSE
		 WHERE id IN (SELECT composite FROM composite_role WHERE child_role = $1)
		   AND NOT EXISTS (SELECT 1 FROM composite_role c
		                   WHERE c.composite = keycloak_role.id AND c.child_role <> $1)`,
		id); err != nil {
		return classify(err)
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM keycloak_role WHERE realm_id = $1 AND id = $2`, realmID, id)
	if err != nil {
		return classify(err)
	}
	// Before the commit on purpose: a role that is not there must leave the
	// flags it never touched alone, so the rollback takes the UPDATE with it.
	if err := affectedOne(tag.RowsAffected()); err != nil {
		return err
	}
	return tx.Commit(ctx)
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
	_, err := r.pool.Exec(ctx,
		`DELETE FROM composite_role WHERE composite = $1 AND child_role = $2`,
		roleID, childRoleID)
	return classify(err)
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
	rows, err := r.pool.Query(ctx,
		`SELECT u.id, u.realm_id, u.username, u.email, u.email_verified, u.enabled,
		        u.first_name, u.last_name, u.created_timestamp, u.attributes, u.required_actions, u.not_before
		 FROM user_entity u
		 JOIN user_role_mapping m ON m.user_id = u.id
		 WHERE u.realm_id = $1 AND m.role_id = $2
		 ORDER BY u.username`, realmID, roleID)
	if err != nil {
		return nil, classify(err)
	}
	return scanUsers(rows)
}

// insertRoleAttributes writes every value of every attribute, ordinal by
// position in the slice, so the order the caller gave them in round-trips.
func insertRoleAttributes(ctx context.Context, tx pgx.Tx, m *model.Role) error {
	for name, values := range m.Attributes {
		for i, v := range values {
			if _, err := tx.Exec(ctx,
				`INSERT INTO role_attribute (role_id, name, value, ordinal) VALUES ($1, $2, $3, $4)`,
				m.ID, name, v, i); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadRoleAttributes fills Attributes on roles already scanned. It runs one
// query for the whole set rather than one per role: ListClientRoles returns 21
// on the admin container alone. The IN list's placeholders are numbered from
// scratch here rather than reused from elsewhere, since $n numbering is
// statement-local.
func (r *roleRepo) loadRoleAttributes(ctx context.Context, roles []*model.Role) error {
	if len(roles) == 0 {
		return nil
	}
	byID := make(map[string]*model.Role, len(roles))
	args := make([]any, 0, len(roles))
	placeholders := make([]string, 0, len(roles))
	for i, role := range roles {
		byID[role.ID] = role
		args = append(args, role.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
	}
	rows, err := r.pool.Query(ctx,
		`SELECT role_id, name, value FROM role_attribute
		 WHERE role_id IN (`+strings.Join(placeholders, ",")+`)
		 ORDER BY role_id, name, ordinal`, args...)
	if err != nil {
		return classify(err)
	}
	defer rows.Close()
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

func (r *sessionRepo) DeleteUserSessions(ctx context.Context, realmID, userID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM user_session WHERE realm_id = $1 AND user_id = $2`, realmID, userID)
	return classify(err)
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

type groupRepo struct{ pool *pgxpool.Pool }

// Create writes the group row and its attributes in one transaction, so a
// group with attributes never exists half-written.
func (r *groupRepo) Create(ctx context.Context, m *model.Group) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO keycloak_group (id, realm_id, parent_id, name) VALUES ($1, $2, $3, $4)`,
		m.ID, m.RealmID, m.ParentID, m.Name); err != nil {
		return classify(err)
	}
	if err := insertGroupAttributes(ctx, tx, m); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

func (r *groupRepo) ByID(ctx context.Context, realmID, id string) (*model.Group, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, parent_id, name FROM keycloak_group
		 WHERE realm_id = $1 AND id = $2`, realmID, id)
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
// nothing in the admin API reparents a group.
func (r *groupRepo) Update(ctx context.Context, m *model.Group) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE keycloak_group SET name = $1 WHERE realm_id = $2 AND id = $3`,
		m.Name, m.RealmID, m.ID)
	if err != nil {
		return classify(err)
	}
	if err := affectedOne(tag.RowsAffected()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM group_attribute WHERE group_id = $1`, m.ID); err != nil {
		return classify(err)
	}
	if err := insertGroupAttributes(ctx, tx, m); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

// Delete removes the group and its whole subtree. The subtree is walked here
// rather than cascaded by the schema: parent_id is ” for a top-level group and
// a foreign key cannot point at ” , so the column carries no REFERENCES
// clause. See the sqlite driver's copy for the defect that found this.
func (r *groupRepo) Delete(ctx context.Context, realmID, id string) error {
	if _, err := r.ByID(ctx, realmID, id); err != nil {
		return err
	}
	ids, err := r.subtree(ctx, realmID, id)
	if err != nil {
		return err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, gid := range ids {
		if _, err := tx.Exec(ctx,
			`DELETE FROM keycloak_group WHERE realm_id = $1 AND id = $2`, realmID, gid); err != nil {
			return classify(err)
		}
	}
	return tx.Commit(ctx)
}

// subtree is the group and every group under it, leaves first.
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
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// ListTopLevel is what GET /groups answers: the groups with no parent.
func (r *groupRepo) ListTopLevel(ctx context.Context, realmID string) ([]*model.Group, error) {
	return r.list(ctx, `WHERE realm_id = $1 AND parent_id = '' ORDER BY name`, realmID)
}

func (r *groupRepo) ListChildren(ctx context.Context, realmID, parentID string) ([]*model.Group, error) {
	return r.list(ctx, `WHERE realm_id = $1 AND parent_id = $2 ORDER BY name`, realmID, parentID)
}

func (r *groupRepo) list(ctx context.Context, where string, args ...any) ([]*model.Group, error) {
	rows, err := r.pool.Query(ctx,
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

// ListAll is every group at any depth, which the count and the search share.
func (r *groupRepo) ListAll(ctx context.Context, realmID string) ([]*model.Group, error) {
	return r.list(ctx, `WHERE realm_id = $1 ORDER BY name`, realmID)
}

// Ancestry walks parent_id upwards and returns the chain nearest last.
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

// Members are the users assigned to this group directly.
func (r *groupRepo) Members(ctx context.Context, realmID, groupID string) ([]*model.User, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT u.id, u.realm_id, u.username, u.email, u.email_verified, u.enabled,
		        u.first_name, u.last_name, u.created_timestamp, u.attributes, u.required_actions, u.not_before
		 FROM user_entity u
		 JOIN group_membership m ON m.user_id = u.id
		 WHERE u.realm_id = $1 AND m.group_id = $2
		 ORDER BY u.username`, realmID, groupID)
	if err != nil {
		return nil, classify(err)
	}
	return scanUsers(rows)
}

// AddMember is idempotent: the measured PUT answers 204 for a membership the
// user already had.
func (r *groupRepo) AddMember(ctx context.Context, groupID, userID string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO group_membership (group_id, user_id) VALUES ($1, $2)
		 ON CONFLICT DO NOTHING`, groupID, userID)
	return classify(err)
}

// RemoveMember reports no error for a membership that is not there.
func (r *groupRepo) RemoveMember(ctx context.Context, groupID, userID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM group_membership WHERE group_id = $1 AND user_id = $2`, groupID, userID)
	return classify(err)
}

func (r *groupRepo) ListUserGroups(ctx context.Context, realmID, userID string) ([]*model.Group, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT g.id, g.realm_id, g.parent_id, g.name FROM keycloak_group g
		 JOIN group_membership m ON m.group_id = g.id
		 WHERE g.realm_id = $1 AND m.user_id = $2 ORDER BY g.name`, realmID, userID)
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
	rows, err := r.pool.Query(ctx,
		`SELECT g.id, g.realm_id, g.parent_id, g.name FROM keycloak_group g
		 JOIN realm_default_group d ON d.group_id = g.id
		 WHERE d.realm_id = $1 ORDER BY g.name`, realmID)
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
	_, err := r.pool.Exec(ctx,
		`INSERT INTO realm_default_group (realm_id, group_id) VALUES ($1, $2)
		 ON CONFLICT DO NOTHING`, realmID, groupID)
	return classify(err)
}

func (r *groupRepo) RemoveDefaultGroup(ctx context.Context, realmID, groupID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM realm_default_group WHERE realm_id = $1 AND group_id = $2`, realmID, groupID)
	return classify(err)
}

func insertGroupAttributes(ctx context.Context, tx pgx.Tx, m *model.Group) error {
	for name, values := range m.Attributes {
		for i, v := range values {
			if _, err := tx.Exec(ctx,
				`INSERT INTO group_attribute (group_id, name, value, ordinal) VALUES ($1, $2, $3, $4)`,
				m.ID, name, v, i); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadGroupAttributes fills Attributes on groups already scanned, one query for
// the whole set.
func (r *groupRepo) loadGroupAttributes(ctx context.Context, groups []*model.Group) error {
	if len(groups) == 0 {
		return nil
	}
	byID := make(map[string]*model.Group, len(groups))
	args := make([]any, 0, len(groups))
	placeholders := make([]string, 0, len(groups))
	for i, g := range groups {
		byID[g.ID] = g
		args = append(args, g.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
	}
	rows, err := r.pool.Query(ctx,
		`SELECT group_id, name, value FROM group_attribute
		 WHERE group_id IN (`+strings.Join(placeholders, ",")+`)
		 ORDER BY group_id, name, ordinal`, args...)
	if err != nil {
		return classify(err)
	}
	defer rows.Close()
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

func collectGroups(rows pgx.Rows) ([]*model.Group, error) {
	defer rows.Close()
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

// AssignToGroup is AssignToUser's mirror, idempotent for the same measured
// reason.
func (r *roleRepo) AssignToGroup(ctx context.Context, groupID, roleID string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO group_role_mapping (group_id, role_id) VALUES ($1, $2)
		 ON CONFLICT DO NOTHING`, groupID, roleID)
	return classify(err)
}

// RemoveFromGroup reports no error for a mapping that is not there.
func (r *roleRepo) RemoveFromGroup(ctx context.Context, groupID, roleID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM group_role_mapping WHERE group_id = $1 AND role_id = $2`, groupID, roleID)
	return classify(err)
}

func (r *roleRepo) ListGroupRoles(ctx context.Context, groupID string) ([]*model.Role, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT r.id, r.realm_id, r.client_id, r.name, r.description, r.composite
		 FROM keycloak_role r
		 JOIN group_role_mapping m ON m.role_id = r.id
		 WHERE m.group_id = $1 ORDER BY r.name`, groupID)
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

// The scope mappings of a client and of a client scope. Two tables, one shape,
// and the six methods are spelled out rather than parameterised by a container
// kind: a kind argument is the query that forgets which holder it meant, which
// is what 0011 already refused for the user and group mirrors.
//
// Both adds swallow a repeat and both removes swallow a missing row, because
// both verbs are measured idempotent on both containers.
//
// ORDER BY name is Gloak's, not Keycloak's. Keycloak serves these in its
// realm-role-listing order, which is not reproducible across container starts,
// so the conformance cases sort both sides and this picks the order that at
// least does not move between two reads of one Gloak.

func (r *roleRepo) AddClientScopeMapping(ctx context.Context, clientID, roleID string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO scope_mapping (client_id, role_id) VALUES ($1, $2)
		 ON CONFLICT DO NOTHING`, clientID, roleID)
	return classify(err)
}

func (r *roleRepo) RemoveClientScopeMapping(ctx context.Context, clientID, roleID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM scope_mapping WHERE client_id = $1 AND role_id = $2`, clientID, roleID)
	return classify(err)
}

func (r *roleRepo) ListClientScopeMappings(ctx context.Context, clientID string) ([]*model.Role, error) {
	return r.scopeMappings(ctx,
		`SELECT r.id, r.realm_id, r.client_id, r.name, r.description, r.composite
		 FROM keycloak_role r
		 JOIN scope_mapping m ON m.role_id = r.id
		 WHERE m.client_id = $1 ORDER BY r.name`, clientID)
}

func (r *roleRepo) AddClientScopeScopeMapping(ctx context.Context, clientScopeID, roleID string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO client_scope_role_mapping (client_scope_id, role_id) VALUES ($1, $2)
		 ON CONFLICT DO NOTHING`, clientScopeID, roleID)
	return classify(err)
}

func (r *roleRepo) RemoveClientScopeScopeMapping(ctx context.Context, clientScopeID, roleID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM client_scope_role_mapping
		 WHERE client_scope_id = $1 AND role_id = $2`, clientScopeID, roleID)
	return classify(err)
}

func (r *roleRepo) ListClientScopeScopeMappings(ctx context.Context, clientScopeID string) ([]*model.Role, error) {
	return r.scopeMappings(ctx,
		`SELECT r.id, r.realm_id, r.client_id, r.name, r.description, r.composite
		 FROM keycloak_role r
		 JOIN client_scope_role_mapping m ON m.role_id = r.id
		 WHERE m.client_scope_id = $1 ORDER BY r.name`, clientScopeID)
}

// scopeMappings is what the two listings share once the join differs. The
// attribute load is part of it because `.../composite?briefRepresentation=false`
// serves a role's attributes, so a scope mapping read reaches the same rows a
// role read does.
func (r *roleRepo) scopeMappings(ctx context.Context, query, id string) ([]*model.Role, error) {
	rows, err := r.pool.Query(ctx, query, id)
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

// clientScopeColumns is spelled once so the statements below cannot drift apart
// on the order scanClientScope depends on. prefixedClientScopeColumns is the
// same list qualified for the two joins.
const (
	clientScopeColumns         = `id, realm_id, name, description, protocol, attributes, protocol_mappers`
	prefixedClientScopeColumns = `s.id, s.realm_id, s.name, s.description, s.protocol, s.attributes, s.protocol_mappers`
)

type clientScopeRepo struct{ pool *pgxpool.Pool }

func (r *clientScopeRepo) Create(ctx context.Context, m *model.ClientScope) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO client_scope (`+clientScopeColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		m.ID, m.RealmID, m.Name, m.Description, m.Protocol,
		encode(m.Attributes), encode(m.ProtocolMappers))
	return classify(err)
}

func (r *clientScopeRepo) ByID(ctx context.Context, realmID, id string) (*model.ClientScope, error) {
	return scanClientScope(r.pool.QueryRow(ctx,
		`SELECT `+clientScopeColumns+` FROM client_scope WHERE realm_id = $1 AND id = $2`,
		realmID, id))
}

func (r *clientScopeRepo) ByName(ctx context.Context, realmID, name string) (*model.ClientScope, error) {
	return scanClientScope(r.pool.QueryRow(ctx,
		`SELECT `+clientScopeColumns+` FROM client_scope WHERE realm_id = $1 AND name = $2`,
		realmID, name))
}

func (r *clientScopeRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.ClientScope, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+clientScopeColumns+` FROM client_scope WHERE realm_id = $1 ORDER BY name`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	return collectClientScopes(rows)
}

func (r *clientScopeRepo) Update(ctx context.Context, m *model.ClientScope) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE client_scope SET name = $1, description = $2, protocol = $3, attributes = $4,
		 protocol_mappers = $5 WHERE realm_id = $6 AND id = $7`,
		m.Name, m.Description, m.Protocol, encode(m.Attributes),
		encode(m.ProtocolMappers), m.RealmID, m.ID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

func (r *clientScopeRepo) Delete(ctx context.Context, realmID, id string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM client_scope WHERE realm_id = $1 AND id = $2`, realmID, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

// ProtocolMapperOwner is clientRepo's over the other container - see there for
// why there is no realm in the query.
func (r *clientScopeRepo) ProtocolMapperOwner(ctx context.Context, mapperID string) (string, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, protocol_mappers FROM client_scope`)
	if err != nil {
		return "", classify(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, mappers string
		if err := rows.Scan(&id, &mappers); err != nil {
			return "", classify(err)
		}
		if store.HoldsProtocolMapper(mappers, mapperID) {
			return id, nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", classify(err)
	}
	return "", store.ErrNotFound
}

func (r *clientScopeRepo) ListRealmDefaults(ctx context.Context, realmID string, defaultScope bool) ([]*model.ClientScope, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+prefixedClientScopeColumns+` FROM client_scope s
		 JOIN realm_default_client_scope d ON d.client_scope_id = s.id
		 WHERE d.realm_id = $1 AND d.default_scope = $2 ORDER BY d.ordinal`,
		realmID, boolToInt(defaultScope))
	if err != nil {
		return nil, classify(err)
	}
	return collectClientScopes(rows)
}

func (r *clientScopeRepo) AddRealmDefault(ctx context.Context, realmID, scopeID string, defaultScope bool) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO realm_default_client_scope (realm_id, client_scope_id, default_scope, ordinal)
		 SELECT $1, $2, $3, COALESCE(MAX(ordinal), -1) + 1
		 FROM realm_default_client_scope WHERE realm_id = $4`,
		realmID, scopeID, boolToInt(defaultScope), realmID)
	return classify(err)
}

func (r *clientScopeRepo) RemoveRealmDefault(ctx context.Context, realmID, scopeID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM realm_default_client_scope WHERE realm_id = $1 AND client_scope_id = $2`,
		realmID, scopeID)
	return classify(err)
}

func (r *clientScopeRepo) ListClientScopes(ctx context.Context, clientID string, defaultScope bool) ([]*model.ClientScope, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+prefixedClientScopeColumns+` FROM client_scope s
		 JOIN client_client_scope c ON c.client_scope_id = s.id
		 WHERE c.client_id = $1 AND c.default_scope = $2 ORDER BY s.name`,
		clientID, boolToInt(defaultScope))
	if err != nil {
		return nil, classify(err)
	}
	return collectClientScopes(rows)
}

func (r *clientScopeRepo) AddClientScope(ctx context.Context, clientID, scopeID string, defaultScope bool) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO client_client_scope (client_id, client_scope_id, default_scope)
		 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		clientID, scopeID, boolToInt(defaultScope))
	return classify(err)
}

func (r *clientScopeRepo) RemoveClientScope(ctx context.Context, clientID, scopeID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM client_client_scope WHERE client_id = $1 AND client_scope_id = $2`,
		clientID, scopeID)
	return classify(err)
}

func scanClientScope(row scanner) (*model.ClientScope, error) {
	m := &model.ClientScope{}
	var attributes, mappers string
	if err := row.Scan(&m.ID, &m.RealmID, &m.Name, &m.Description, &m.Protocol,
		&attributes, &mappers); err != nil {
		return nil, classify(err)
	}
	if err := decode(attributes, &m.Attributes); err != nil {
		return nil, err
	}
	if err := decode(mappers, &m.ProtocolMappers); err != nil {
		return nil, err
	}
	return m, nil
}

func collectClientScopes(rows pgx.Rows) ([]*model.ClientScope, error) {
	defer rows.Close()
	out := []*model.ClientScope{}
	for rows.Next() {
		m, err := scanClientScope(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

// requiredActionColumns is the row of required_action_provider, in the order
// the representation serialises them - so a reader comparing this list against
// the measured body does not have to reorder anything in their head.
const requiredActionColumns = `id, realm_id, alias, name, provider_id, enabled, default_action, priority, config`

type requiredActionRepo struct{ pool *pgxpool.Pool }

func (r *requiredActionRepo) Create(ctx context.Context, m *model.RequiredActionProvider) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO required_action_provider (`+requiredActionColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		m.ID, m.RealmID, m.Alias, m.Name, m.ProviderID, m.Enabled,
		m.DefaultAction, m.Priority, encode(m.Config))
	return classify(err)
}

func (r *requiredActionRepo) ByAlias(ctx context.Context, realmID, alias string) (*model.RequiredActionProvider, error) {
	return scanRequiredAction(r.pool.QueryRow(ctx,
		`SELECT `+requiredActionColumns+` FROM required_action_provider
		 WHERE realm_id = $1 AND alias = $2 ORDER BY priority, id LIMIT 1`,
		realmID, alias))
}

func (r *requiredActionRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.RequiredActionProvider, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+requiredActionColumns+` FROM required_action_provider
		 WHERE realm_id = $1 ORDER BY priority, id`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	return collectRequiredActions(rows)
}

// Update deliberately omits provider_id. PUT /required-actions/{alias} reads
// providerId off the wire and discards it, measured, so the column is written
// once at registration and never again.
func (r *requiredActionRepo) Update(ctx context.Context, m *model.RequiredActionProvider) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE required_action_provider SET alias = $1, name = $2, enabled = $3,
		 default_action = $4, priority = $5, config = $6 WHERE realm_id = $7 AND id = $8`,
		m.Alias, m.Name, m.Enabled, m.DefaultAction, m.Priority,
		encode(m.Config), m.RealmID, m.ID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

func (r *requiredActionRepo) Delete(ctx context.Context, realmID, id string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM required_action_provider WHERE realm_id = $1 AND id = $2`, realmID, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

func scanRequiredAction(row scanner) (*model.RequiredActionProvider, error) {
	m := &model.RequiredActionProvider{}
	var config string
	if err := row.Scan(&m.ID, &m.RealmID, &m.Alias, &m.Name, &m.ProviderID,
		&m.Enabled, &m.DefaultAction, &m.Priority, &config); err != nil {
		return nil, classify(err)
	}
	if err := decode(config, &m.Config); err != nil {
		return nil, err
	}
	return m, nil
}

func collectRequiredActions(rows pgx.Rows) ([]*model.RequiredActionProvider, error) {
	defer rows.Close()
	out := []*model.RequiredActionProvider{}
	for rows.Next() {
		m, err := scanRequiredAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

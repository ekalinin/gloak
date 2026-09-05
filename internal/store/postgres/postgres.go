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

func (s *Store) Organizations() store.OrganizationRepo {
	return &organizationRepo{s.pool}
}

func (s *Store) Authz() store.AuthzRepo {
	return &authzRepo{s.pool}
}

func (s *Store) IdentityProviders() store.IdentityProviderRepo {
	return &identityProviderRepo{s.pool}
}

func (s *Store) IdentityProviderMappers() store.IdentityProviderMapperRepo {
	return &identityProviderMapperRepo{s.pool}
}

func (s *Store) Components() store.ComponentRepo {
	return &componentRepo{s.pool}
}

func (s *Store) Localizations() store.LocalizationRepo {
	return &localizationRepo{s.pool}
}

func (s *Store) ClientInitialAccess() store.ClientInitialAccessRepo {
	return &clientInitialAccessRepo{s.pool}
}

func (s *Store) AuthenticationFlows() store.AuthenticationFlowRepo {
	return &authenticationFlowRepo{s.pool}
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
		 redirect_uris, web_origins, attributes, protocol_mappers,
		 EXISTS (SELECT 1 FROM authz_resource_server a WHERE a.client_id = client.id)
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
		 redirect_uris, web_origins, attributes, protocol_mappers,
		 EXISTS (SELECT 1 FROM authz_resource_server a WHERE a.client_id = client.id)
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
		 redirect_uris, web_origins, attributes, protocol_mappers,
		 EXISTS (SELECT 1 FROM authz_resource_server a WHERE a.client_id = client.id)
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
		if err := r.loadNodes(ctx, m); err != nil {
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
	return m, r.loadNodes(ctx, m)
}

// loadNodes fills RegisteredNodes, and leaves it **nil** when the client has
// none rather than setting an empty map. The distinction is the wire's: a
// client with no node omits `registeredNodes` entirely, measured, and
// `omitempty` on the representation cannot tell an empty map from a nil one.
func (r *clientRepo) loadNodes(ctx context.Context, m *model.Client) error {
	rows, err := r.pool.Query(ctx,
		`SELECT node, registered_at FROM client_node WHERE client_id = $1`, m.ID)
	if err != nil {
		return classify(err)
	}
	defer rows.Close()

	m.RegisteredNodes = nil
	for rows.Next() {
		var node string
		var at int64
		if err := rows.Scan(&node, &at); err != nil {
			return classify(err)
		}
		if m.RegisteredNodes == nil {
			m.RegisteredNodes = map[string]int64{}
		}
		m.RegisteredNodes[node] = at
	}
	return classify(rows.Err())
}

// RegisterNode upserts, which is measured: the same node name posted twice
// answers 204 both times and leaves one entry.
func (r *clientRepo) RegisterNode(ctx context.Context, clientID, node string, at int64) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO client_node (client_id, node, registered_at) VALUES ($1, $2, $3)
		 ON CONFLICT (client_id, node) DO UPDATE SET registered_at = excluded.registered_at`,
		clientID, node, at)
	return classify(err)
}

func (r *clientRepo) UnregisterNode(ctx context.Context, clientID, node string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM client_node WHERE client_id = $1 AND node = $2`, clientID, node)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
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
		&redirectURIs, &webOrigins, &attributes, &protocolMappers,
		// The flag is the subquery in the three SELECTs above, never a column.
		&m.AuthorizationServicesEnabled)
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

func (r *userRepo) ListFederatedIdentities(ctx context.Context, realmID, userID string) ([]model.FederatedIdentity, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT identity_provider, external_user_id, external_username
		   FROM federated_identity WHERE realm_id = $1 AND user_id = $2 ORDER BY seq`,
		realmID, userID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()

	out := []model.FederatedIdentity{}
	for rows.Next() {
		var fi model.FederatedIdentity
		if err := rows.Scan(&fi.IdentityProvider, &fi.UserID, &fi.Username); err != nil {
			return nil, classify(err)
		}
		out = append(out, fi)
	}
	return out, classify(rows.Err())
}

// LinkFederatedIdentity numbers the new row inside the same transaction that
// inserts it, which is what makes ListFederatedIdentities' insertion order hold
// under two callers at once.
func (r *userRepo) LinkFederatedIdentity(ctx context.Context, realmID, userID string, fi model.FederatedIdentity) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var seq int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(seq), -1) + 1 FROM federated_identity WHERE realm_id = $1 AND user_id = $2`,
		realmID, userID).Scan(&seq); err != nil {
		return classify(err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO federated_identity
		   (realm_id, user_id, identity_provider, external_user_id, external_username, seq)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		realmID, userID, fi.IdentityProvider, fi.UserID, fi.Username, seq); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

func (r *userRepo) UnlinkFederatedIdentity(ctx context.Context, realmID, userID, provider string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM federated_identity
		   WHERE realm_id = $1 AND user_id = $2 AND identity_provider = $3`,
		realmID, userID, provider)
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

const userSessionColumns = `id, realm_id, user_id, username, started_at, last_refresh, expires_at`

func (r *sessionRepo) ListUserSessionsByRealm(ctx context.Context, realmID string) ([]*model.UserSession, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+userSessionColumns+` FROM user_session WHERE realm_id = $1 ORDER BY id`, realmID)
	return collectUserSessions(rows, err)
}

func (r *sessionRepo) ListUserSessionsByUser(ctx context.Context, realmID, userID string) ([]*model.UserSession, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+userSessionColumns+` FROM user_session
		 WHERE realm_id = $1 AND user_id = $2 ORDER BY id`, realmID, userID)
	return collectUserSessions(rows, err)
}

func (r *sessionRepo) ListUserSessionsByClient(ctx context.Context, realmID, clientID string) ([]*model.UserSession, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+prefixed(userSessionColumns, "s")+` FROM user_session s
		 JOIN client_session cs ON cs.user_session_id = s.id
		 WHERE s.realm_id = $1 AND cs.client_id = $2 ORDER BY s.id`, realmID, clientID)
	return collectUserSessions(rows, err)
}

func (r *sessionRepo) ListClientSessions(ctx context.Context, userSessionID string) ([]*model.ClientSession, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_session_id, client_id, scope, started_at
		 FROM client_session WHERE user_session_id = $1 ORDER BY id`, userSessionID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []*model.ClientSession{}
	for rows.Next() {
		m, err := scanClientSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

func collectUserSessions(rows pgx.Rows, err error) ([]*model.UserSession, error) {
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []*model.UserSession{}
	for rows.Next() {
		m, err := scanUserSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

// prefixed qualifies a comma-separated column list with a table alias, so the
// one join in this repository does not restate the column order that
// scanUserSession reads.
func prefixed(columns, alias string) string {
	parts := strings.Split(columns, ", ")
	for i, p := range parts {
		parts[i] = alias + "." + p
	}
	return strings.Join(parts, ", ")
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
		`INSERT INTO keycloak_group (id, realm_id, parent_id, name, organization_id)
		 VALUES ($1, $2, $3, $4, $5)`,
		m.ID, m.RealmID, m.ParentID, m.Name, nullableOrganizationID(m.OrganizationID)); err != nil {
		return classify(err)
	}
	if err := insertGroupAttributes(ctx, tx, m); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

func (r *groupRepo) ByID(ctx context.Context, realmID, id string) (*model.Group, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, parent_id, name, organization_id FROM keycloak_group
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
	return r.list(ctx, `WHERE realm_id = $1 AND parent_id = '' AND organization_id IS NULL
		 ORDER BY name`, realmID)
}

func (r *groupRepo) ListChildren(ctx context.Context, realmID, parentID string) ([]*model.Group, error) {
	return r.list(ctx, `WHERE realm_id = $1 AND parent_id = $2 ORDER BY name`, realmID, parentID)
}

func (r *groupRepo) list(ctx context.Context, where string, args ...any) ([]*model.Group, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, realm_id, parent_id, name, organization_id FROM keycloak_group `+where, args...)
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
	return r.list(ctx, `WHERE realm_id = $1 AND organization_id IS NULL ORDER BY name`, realmID)
}

// ListOrganizationAll is every group of one organization, its hidden root
// excluded - sqlite.go's twin, and the comment there says why the root is
// dropped here rather than by each caller.
func (r *groupRepo) ListOrganizationAll(ctx context.Context, realmID, orgID string) ([]*model.Group, error) {
	return r.list(ctx, `WHERE realm_id = $1 AND organization_id = $2 AND parent_id <> ''
		 ORDER BY name`, realmID, orgID)
}

// OrganizationRoot is the one row of the organization with no parent.
func (r *groupRepo) OrganizationRoot(ctx context.Context, realmID, orgID string) (*model.Group, error) {
	groups, err := r.list(ctx, `WHERE realm_id = $1 AND organization_id = $2 AND parent_id = ''`,
		realmID, orgID)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, store.ErrNotFound
	}
	return groups[0], nil
}

// Move reparents one group, sqlite.go's twin.
func (r *groupRepo) Move(ctx context.Context, realmID, id, parentID string) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE keycloak_group SET parent_id = $1 WHERE realm_id = $2 AND id = $3`,
		parentID, realmID, id)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
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
		`SELECT g.id, g.realm_id, g.parent_id, g.name, g.organization_id FROM keycloak_group g
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
		`SELECT g.id, g.realm_id, g.parent_id, g.name, g.organization_id FROM keycloak_group g
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
	var org *string
	if err := row.Scan(&m.ID, &m.RealmID, &m.ParentID, &m.Name, &org); err != nil {
		return nil, classify(err)
	}
	if org != nil {
		m.OrganizationID = *org
	}
	return m, nil
}

// nullableOrganizationID writes NULL for a realm group, sqlite.go's twin.
func nullableOrganizationID(id string) any {
	if id == "" {
		return nil
	}
	return id
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
		m.ID, m.RealmID, m.Alias, m.Name, m.ProviderID, boolToInt(m.Enabled),
		boolToInt(m.DefaultAction), m.Priority, encode(m.Config))
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

// Update writes every mutable column, provider_id included. Which fields a
// request may move is internal/admin's decision and is made there alone - see
// store.RequiredActionRepo.Update for why this interface stopped making it too.
func (r *requiredActionRepo) Update(ctx context.Context, m *model.RequiredActionProvider) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE required_action_provider SET alias = $1, name = $2, provider_id = $3,
		 enabled = $4, default_action = $5, priority = $6, config = $7
		 WHERE realm_id = $8 AND id = $9`,
		m.Alias, m.Name, m.ProviderID, boolToInt(m.Enabled),
		boolToInt(m.DefaultAction), m.Priority, encode(m.Config), m.RealmID, m.ID)
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

// scanRequiredAction reads enabled and default_action through ints, because
// the migration declares them INTEGER in both drivers - see boolToInt - and
// pgx will not encode a Go bool into an int4 or decode one back. SQLite's
// driver converts either way and hid this until the shared driver conformance
// covered the table.
func scanRequiredAction(row scanner) (*model.RequiredActionProvider, error) {
	m := &model.RequiredActionProvider{}
	var config string
	var enabled, defaultAction int
	if err := row.Scan(&m.ID, &m.RealmID, &m.Alias, &m.Name, &m.ProviderID,
		&enabled, &defaultAction, &m.Priority, &config); err != nil {
		return nil, classify(err)
	}
	m.Enabled, m.DefaultAction = enabled != 0, defaultAction != 0
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

type organizationRepo struct{ pool *pgxpool.Pool }

// Create writes the row, its domains and its attributes in one transaction, so
// an organization with domains never exists half-written - groupRepo.Create's
// shape, for the same reason.
func (r *organizationRepo) Create(ctx context.Context, m *model.Organization) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`INSERT INTO organization
		   (id, realm_id, name, alias, enabled, description, redirect_url)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		m.ID, m.RealmID, m.Name, m.Alias, boolToInt(m.Enabled),
		m.Description, m.RedirectURL); err != nil {
		return classify(err)
	}
	if err := insertOrganizationChildren(ctx, tx, m); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

// Update writes every field back except the alias.
//
// **alias is not in the statement on purpose.** It is immutable: a PUT carrying
// a different one, or omitting it after a rename so that the derived value
// differs, was measured answering 400 "Cannot change the alias". A driver able
// to write it would offer a change nobody has measured, and the handler's
// refusal would be the only thing standing between a caller and it.
func (r *organizationRepo) Update(ctx context.Context, m *model.Organization) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE organization
		    SET name = $1, enabled = $2, description = $3, redirect_url = $4
		  WHERE realm_id = $5 AND id = $6`,
		m.Name, boolToInt(m.Enabled), m.Description, m.RedirectURL,
		m.RealmID, m.ID)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM organization_domain WHERE organization_id = $1`, m.ID); err != nil {
		return classify(err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM organization_attribute WHERE organization_id = $1`, m.ID); err != nil {
		return classify(err)
	}
	if err := insertOrganizationChildren(ctx, tx, m); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

// Delete removes the row; the schema cascades the domains and the attributes,
// whose foreign keys are real.
func (r *organizationRepo) Delete(ctx context.Context, realmID, id string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM organization WHERE realm_id = $1 AND id = $2`, realmID, id)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (r *organizationRepo) ByID(ctx context.Context, realmID, id string) (*model.Organization, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, realm_id, name, alias, enabled, description, redirect_url
		   FROM organization WHERE realm_id = $1 AND id = $2`, realmID, id)
	m, err := scanOrganization(row)
	if err != nil {
		return nil, err
	}
	if err := r.loadOrganizationChildren(ctx, []*model.Organization{m}); err != nil {
		return nil, err
	}
	return m, nil
}

func (r *organizationRepo) List(ctx context.Context, realmID string) ([]*model.Organization, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, realm_id, name, alias, enabled, description, redirect_url
		   FROM organization WHERE realm_id = $1 ORDER BY name`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectOrganizations(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadOrganizationChildren(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ByDomain matches case-insensitively, which is what the measured refusal
// implies: a domain is an e-mail domain and Keycloak stores it folded.
func (r *organizationRepo) ByDomain(ctx context.Context, realmID, domain string) (*model.Organization, error) {
	var id string
	err := r.pool.QueryRow(ctx,
		`SELECT o.id FROM organization o
		   JOIN organization_domain d ON d.organization_id = o.id
		  WHERE o.realm_id = $1 AND LOWER(d.name) = LOWER($2) LIMIT 1`,
		realmID, domain).Scan(&id)
	if err != nil {
		return nil, classify(err)
	}
	return r.ByID(ctx, realmID, id)
}

// AddMember inserts the pair. The composite primary key is what turns a repeat
// into ErrConflict, which is the measured 409.
func (r *organizationRepo) AddMember(ctx context.Context, orgID, userID string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO organization_member (organization_id, user_id) VALUES ($1, $2)`,
		orgID, userID)
	return classify(err)
}

// RemoveMember deletes the pair, reporting ErrNotFound when there was none -
// the delete is not idempotent and the second one is a 404.
func (r *organizationRepo) RemoveMember(ctx context.Context, orgID, userID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM organization_member WHERE organization_id = $1 AND user_id = $2`,
		orgID, userID)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (r *organizationRepo) IsMember(ctx context.Context, orgID, userID string) (bool, error) {
	var one int
	err := r.pool.QueryRow(ctx,
		`SELECT 1 FROM organization_member WHERE organization_id = $1 AND user_id = $2`,
		orgID, userID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, classify(err)
	}
	return true, nil
}

// Members selects the user rows themselves rather than ids, because the member
// representation **is** a user representation and a second round trip per
// member would be a second chance for the two to disagree. The column list is
// userRepo.ListByRealm's; the order is the same too, and both are measured.
func (r *organizationRepo) Members(ctx context.Context, orgID string) ([]*model.User, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT u.id, u.realm_id, u.username, u.email, u.email_verified, u.enabled,
		        u.first_name, u.last_name, u.created_timestamp, u.attributes,
		        u.required_actions, u.not_before
		   FROM user_entity u
		   JOIN organization_member m ON m.user_id = u.id
		  WHERE m.organization_id = $1 ORDER BY u.username`, orgID)
	if err != nil {
		return nil, classify(err)
	}
	return scanUsers(rows)
}

// MemberOf returns the organizations one user belongs to.
//
// **The ORDER BY is organization.name and the wire order is not**, which is a
// difference this comment exists to keep: the measured serving order matches
// neither insertion, nor name, nor id, and is explained by nothing, so the two
// cases that serve it carry Case.Unordered. Ordering here is what keeps the two
// drivers from disagreeing with each other, which is a separate promise from
// agreeing with Keycloak.
func (r *organizationRepo) MemberOf(ctx context.Context, realmID, userID string) ([]*model.Organization, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT o.id, o.realm_id, o.name, o.alias, o.enabled, o.description, o.redirect_url
		   FROM organization o
		   JOIN organization_member m ON m.organization_id = o.id
		  WHERE o.realm_id = $1 AND m.user_id = $2 ORDER BY o.name`, realmID, userID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectOrganizations(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadOrganizationChildren(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// insertOrganizationChildren writes the domains and the attributes. Both carry
// an ordinal because both came off the wire in an order a Go map would lose.
func insertOrganizationChildren(ctx context.Context, tx pgx.Tx, m *model.Organization) error {
	for i, d := range m.Domains {
		if _, err := tx.Exec(ctx,
			`INSERT INTO organization_domain (organization_id, name, verified, ordinal)
			 VALUES ($1, $2, $3, $4)`,
			m.ID, d.Name, boolToInt(d.Verified), i); err != nil {
			return err
		}
	}
	for i, a := range m.Attributes {
		for j, v := range a.Values {
			if _, err := tx.Exec(ctx,
				`INSERT INTO organization_attribute (organization_id, name, value, ordinal)
				 VALUES ($1, $2, $3, $4)`,
				m.ID, a.Name, v, i*1000+j); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadOrganizationChildren fills Domains and Attributes on organizations
// already scanned, one query each for the whole set - loadGroupAttributes'
// shape.
func (r *organizationRepo) loadOrganizationChildren(ctx context.Context, orgs []*model.Organization) error {
	if len(orgs) == 0 {
		return nil
	}
	byID := make(map[string]*model.Organization, len(orgs))
	ids := make([]any, 0, len(orgs))
	placeholders := make([]string, 0, len(orgs))
	for i, o := range orgs {
		byID[o.ID] = o
		ids = append(ids, o.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
	}
	in := strings.Join(placeholders, ",")

	rows, err := r.pool.Query(ctx,
		`SELECT organization_id, name, verified FROM organization_domain
		  WHERE organization_id IN (`+in+`) ORDER BY organization_id, ordinal`, ids...)
	if err != nil {
		return classify(err)
	}
	if err := scanOrganizationDomains(rows, byID); err != nil {
		return err
	}

	rows, err = r.pool.Query(ctx,
		`SELECT organization_id, name, value FROM organization_attribute
		  WHERE organization_id IN (`+in+`) ORDER BY organization_id, ordinal`, ids...)
	if err != nil {
		return classify(err)
	}
	return scanOrganizationAttributes(rows, byID)
}

func scanOrganizationDomains(rows pgx.Rows, byID map[string]*model.Organization) error {
	defer rows.Close()
	for rows.Next() {
		var orgID, name string
		var verified int
		if err := rows.Scan(&orgID, &name, &verified); err != nil {
			return err
		}
		o := byID[orgID]
		o.Domains = append(o.Domains, model.OrganizationDomain{Name: name, Verified: verified != 0})
	}
	return classify(rows.Err())
}

func scanOrganizationAttributes(rows pgx.Rows, byID map[string]*model.Organization) error {
	defer rows.Close()
	for rows.Next() {
		var orgID, name, value string
		if err := rows.Scan(&orgID, &name, &value); err != nil {
			return err
		}
		byID[orgID].AddAttribute(name, value)
	}
	return classify(rows.Err())
}

func scanOrganization(row scanner) (*model.Organization, error) {
	m := &model.Organization{}
	var enabled int
	var description *string
	if err := row.Scan(&m.ID, &m.RealmID, &m.Name, &m.Alias, &enabled,
		&description, &m.RedirectURL); err != nil {
		return nil, classify(err)
	}
	m.Enabled = enabled != 0
	// NULL is "never set" and '' is "set to nothing", and the representation
	// tells them apart. See 0018_organization.sql.
	m.Description = description
	return m, nil
}

func collectOrganizations(rows pgx.Rows) ([]*model.Organization, error) {
	defer rows.Close()
	out := []*model.Organization{}
	for rows.Next() {
		m, err := scanOrganization(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

type authzRepo struct{ pool *pgxpool.Pool }

// Upsert writes the three settings, creating the row when it is absent.
//
// ON CONFLICT rather than an UPDATE-then-INSERT because the row's existence is
// the client's authorizationServicesEnabled flag: an update that found nothing
// would have to decide whether to turn the flag on, and that decision belongs
// to the caller in internal/admin rather than to a driver.
func (r *authzRepo) Upsert(ctx context.Context, rs *model.AuthzResourceServer) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO authz_resource_server
		   (client_id, allow_remote_resource_management, policy_enforcement_mode, decision_strategy)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (client_id) DO UPDATE SET
		   allow_remote_resource_management = excluded.allow_remote_resource_management,
		   policy_enforcement_mode = excluded.policy_enforcement_mode,
		   decision_strategy = excluded.decision_strategy`,
		rs.ClientID, boolToInt(rs.AllowRemoteResourceManagement), rs.PolicyEnforcementMode, rs.DecisionStrategy)
	return classify(err)
}

func (r *authzRepo) ByClientID(ctx context.Context, clientID string) (*model.AuthzResourceServer, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT client_id, allow_remote_resource_management, policy_enforcement_mode, decision_strategy
		 FROM authz_resource_server WHERE client_id = $1`, clientID)
	m := &model.AuthzResourceServer{}
	var allowRemote int
	if err := row.Scan(&m.ClientID, &allowRemote, &m.PolicyEnforcementMode, &m.DecisionStrategy); err != nil {
		return nil, classify(err)
	}
	m.AllowRemoteResourceManagement = allowRemote != 0
	return m, nil
}

// DeleteByClientID is idempotent and deliberately does not report ErrNotFound:
// PUT /clients/{uuid} sending authorizationServicesEnabled false twice answers
// 204 both times, so a driver that distinguished the two calls would be
// offering the handler a difference it must not act on.
func (r *authzRepo) DeleteByClientID(ctx context.Context, clientID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM authz_resource_server WHERE client_id = $1`, clientID)
	return classify(err)
}

// authzScopeColumns is the read order every scope query uses, matching
// scanAuthzScope.
const authzScopeColumns = `id, resource_server_id, name, icon_uri, display_name, ordinal`

// CreateScope assigns the ordinal from the resource server's own maximum, the
// way AddRealmDefault does. The ordinal is the settings export's order and
// nothing else reads it.
func (r *authzRepo) CreateScope(ctx context.Context, s *model.AuthzScope) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO authz_scope (id, resource_server_id, name, icon_uri, display_name, ordinal)
		 SELECT $1, $2, $3, $4, $5, COALESCE(MAX(ordinal), -1) + 1
		 FROM authz_scope WHERE resource_server_id = $6`,
		s.ID, s.ClientID, s.Name, s.IconURI, s.DisplayName, s.ClientID)
	return classify(err)
}

// UpdateScope leaves the ordinal alone: a PUT was measured leaving the
// settings export's order unchanged, so the row keeps the position its create
// gave it.
func (r *authzRepo) UpdateScope(ctx context.Context, s *model.AuthzScope) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE authz_scope SET name = $1, icon_uri = $2, display_name = $3
		 WHERE id = $4 AND resource_server_id = $5`,
		s.Name, s.IconURI, s.DisplayName, s.ID, s.ClientID)
	return classify(err)
}

func (r *authzRepo) DeleteScope(ctx context.Context, clientID, scopeID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM authz_scope WHERE id = $1 AND resource_server_id = $2`, scopeID, clientID)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (r *authzRepo) ScopeByID(ctx context.Context, clientID, scopeID string) (*model.AuthzScope, error) {
	return scanAuthzScope(r.pool.QueryRow(ctx,
		`SELECT `+authzScopeColumns+` FROM authz_scope
		 WHERE id = $1 AND resource_server_id = $2`, scopeID, clientID))
}

func (r *authzRepo) ScopeByName(ctx context.Context, clientID, name string) (*model.AuthzScope, error) {
	return scanAuthzScope(r.pool.QueryRow(ctx,
		`SELECT `+authzScopeColumns+` FROM authz_scope
		 WHERE resource_server_id = $1 AND name = $2`, clientID, name))
}

// ListScopes orders by ordinal, which is creation order and which is what
// GET .../settings serves. The listing's name order is applied above this
// layer; see store.AuthzRepo.
func (r *authzRepo) ListScopes(ctx context.Context, clientID string) ([]*model.AuthzScope, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+authzScopeColumns+` FROM authz_scope
		 WHERE resource_server_id = $1 ORDER BY ordinal`, clientID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []*model.AuthzScope{}
	for rows.Next() {
		s := &model.AuthzScope{}
		if err := rows.Scan(&s.ID, &s.ClientID, &s.Name, &s.IconURI, &s.DisplayName, &s.Ordinal); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, classify(rows.Err())
}

func scanAuthzScope(row pgx.Row) (*model.AuthzScope, error) {
	s := &model.AuthzScope{}
	if err := row.Scan(&s.ID, &s.ClientID, &s.Name, &s.IconURI, &s.DisplayName, &s.Ordinal); err != nil {
		return nil, classify(err)
	}
	return s, nil
}

// authzResourceColumns is the read order every resource query uses, matching
// the two scanners below.
const authzResourceColumns = `id, resource_server_id, name, display_name, type, icon_uri,
	owner_managed_access, ordinal`

// CreateResource writes the row and its three child collections in one
// transaction, so a resource with uris never exists half-written -
// organizationRepo.Create's shape, for the same reason.
func (r *authzRepo) CreateResource(ctx context.Context, res *model.AuthzResource) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`INSERT INTO authz_resource
		   (id, resource_server_id, name, display_name, type, icon_uri, owner_managed_access, ordinal)
		 SELECT $1, $2, $3, $4, $5, $6, $7, COALESCE(MAX(ordinal), -1) + 1
		 FROM authz_resource WHERE resource_server_id = $8`,
		res.ID, res.ClientID, res.Name, res.DisplayName, res.Type, res.IconURI,
		boolToInt(res.OwnerManagedAccess), res.ClientID); err != nil {
		return classify(err)
	}
	if err := insertAuthzResourceChildren(ctx, tx, res); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

// UpdateResource leaves the ordinal alone, the way UpdateScope does: the
// settings export's order was measured surviving a PUT.
func (r *authzRepo) UpdateResource(ctx context.Context, res *model.AuthzResource) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE authz_resource
		    SET name = $1, display_name = $2, type = $3, icon_uri = $4, owner_managed_access = $5
		  WHERE id = $6 AND resource_server_id = $7`,
		res.Name, res.DisplayName, res.Type, res.IconURI,
		boolToInt(res.OwnerManagedAccess), res.ID, res.ClientID)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	for _, table := range []string{"authz_resource_uri", "authz_resource_attribute", "authz_resource_scope"} {
		if _, err := tx.Exec(ctx,
			`DELETE FROM `+table+` WHERE resource_id = $1`, res.ID); err != nil {
			return classify(err)
		}
	}
	if err := insertAuthzResourceChildren(ctx, tx, res); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

func (r *authzRepo) DeleteResource(ctx context.Context, clientID, resourceID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM authz_resource WHERE id = $1 AND resource_server_id = $2`, resourceID, clientID)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (r *authzRepo) ResourceByID(ctx context.Context, clientID, resourceID string) (*model.AuthzResource, error) {
	return r.oneAuthzResource(ctx, r.pool.QueryRow(ctx,
		`SELECT `+authzResourceColumns+` FROM authz_resource
		 WHERE id = $1 AND resource_server_id = $2`, resourceID, clientID))
}

func (r *authzRepo) ResourceByName(ctx context.Context, clientID, name string) (*model.AuthzResource, error) {
	return r.oneAuthzResource(ctx, r.pool.QueryRow(ctx,
		`SELECT `+authzResourceColumns+` FROM authz_resource
		 WHERE resource_server_id = $1 AND name = $2`, clientID, name))
}

// ListResources orders by ordinal, which is creation order and which is what
// GET .../settings and GET .../scope/{id}/resources both serve. The listing's
// name order, its six filters and its two bounds are applied above this layer;
// see store.AuthzRepo.
func (r *authzRepo) ListResources(ctx context.Context, clientID string) ([]*model.AuthzResource, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+authzResourceColumns+` FROM authz_resource
		 WHERE resource_server_id = $1 ORDER BY ordinal`, clientID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectAuthzResources(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadAuthzResourceChildren(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *authzRepo) oneAuthzResource(ctx context.Context, row pgx.Row) (*model.AuthzResource, error) {
	res := &model.AuthzResource{}
	var owned int
	if err := row.Scan(&res.ID, &res.ClientID, &res.Name, &res.DisplayName, &res.Type,
		&res.IconURI, &owned, &res.Ordinal); err != nil {
		return nil, classify(err)
	}
	res.OwnerManagedAccess = owned != 0
	if err := r.loadAuthzResourceChildren(ctx, []*model.AuthzResource{res}); err != nil {
		return nil, err
	}
	return res, nil
}

func collectAuthzResources(rows pgx.Rows) ([]*model.AuthzResource, error) {
	defer rows.Close()
	out := []*model.AuthzResource{}
	for rows.Next() {
		res := &model.AuthzResource{}
		var owned int
		if err := rows.Scan(&res.ID, &res.ClientID, &res.Name, &res.DisplayName, &res.Type,
			&res.IconURI, &owned, &res.Ordinal); err != nil {
			return nil, err
		}
		res.OwnerManagedAccess = owned != 0
		out = append(out, res)
	}
	return out, classify(rows.Err())
}

// insertAuthzResourceChildren writes the uris, the attributes and the scope
// links. All three carry an ordinal because all three came off the wire in an
// order a Go map or a Go set would lose - and the uris and the attributes were
// measured chaining in **opposite** directions, so neither can be rebuilt from
// the other.
func insertAuthzResourceChildren(ctx context.Context, tx pgx.Tx, res *model.AuthzResource) error {
	for i, u := range res.URIs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO authz_resource_uri (resource_id, value, ordinal) VALUES ($1, $2, $3)`,
			res.ID, u, i); err != nil {
			return err
		}
	}
	for i, a := range res.Attributes {
		for j, v := range a.Values {
			if _, err := tx.Exec(ctx,
				`INSERT INTO authz_resource_attribute (resource_id, name, value, ordinal)
				 VALUES ($1, $2, $3, $4)`,
				res.ID, a.Name, v, i*1000+j); err != nil {
				return err
			}
		}
	}
	for i, s := range res.ScopeIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO authz_resource_scope (resource_id, scope_id, ordinal) VALUES ($1, $2, $3)`,
			res.ID, s, i); err != nil {
			return err
		}
	}
	return nil
}

// loadAuthzResourceChildren fills URIs, Attributes and ScopeIDs on resources
// already scanned, one query each for the whole set -
// loadOrganizationChildren's shape.
func (r *authzRepo) loadAuthzResourceChildren(ctx context.Context, list []*model.AuthzResource) error {
	if len(list) == 0 {
		return nil
	}
	byID := make(map[string]*model.AuthzResource, len(list))
	ids := make([]any, 0, len(list))
	placeholders := make([]string, 0, len(list))
	for i, res := range list {
		byID[res.ID] = res
		ids = append(ids, res.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
	}
	in := strings.Join(placeholders, ",")

	rows, err := r.pool.Query(ctx,
		`SELECT resource_id, value FROM authz_resource_uri
		  WHERE resource_id IN (`+in+`) ORDER BY resource_id, ordinal`, ids...)
	if err != nil {
		return classify(err)
	}
	if err := scanAuthzResourceStrings(rows, byID, func(res *model.AuthzResource, v string) {
		res.URIs = append(res.URIs, v)
	}); err != nil {
		return err
	}

	rows, err = r.pool.Query(ctx,
		`SELECT resource_id, name, value FROM authz_resource_attribute
		  WHERE resource_id IN (`+in+`) ORDER BY resource_id, ordinal`, ids...)
	if err != nil {
		return classify(err)
	}
	if err := scanAuthzResourceAttributes(rows, byID); err != nil {
		return err
	}

	rows, err = r.pool.Query(ctx,
		`SELECT resource_id, scope_id FROM authz_resource_scope
		  WHERE resource_id IN (`+in+`) ORDER BY resource_id, ordinal`, ids...)
	if err != nil {
		return classify(err)
	}
	return scanAuthzResourceStrings(rows, byID, func(res *model.AuthzResource, v string) {
		res.ScopeIDs = append(res.ScopeIDs, v)
	})
}

func scanAuthzResourceStrings(rows pgx.Rows, byID map[string]*model.AuthzResource,
	add func(*model.AuthzResource, string)) error {
	defer rows.Close()
	for rows.Next() {
		var resourceID, value string
		if err := rows.Scan(&resourceID, &value); err != nil {
			return err
		}
		add(byID[resourceID], value)
	}
	return classify(rows.Err())
}

func scanAuthzResourceAttributes(rows pgx.Rows, byID map[string]*model.AuthzResource) error {
	defer rows.Close()
	for rows.Next() {
		var resourceID, name, value string
		if err := rows.Scan(&resourceID, &name, &value); err != nil {
			return err
		}
		byID[resourceID].AddAttribute(name, value)
	}
	return classify(rows.Err())
}

// authzPolicyColumns is the read order every policy query uses, matching
// collectAuthzPolicies and oneAuthzPolicy.
const authzPolicyColumns = `id, resource_server_id, name, description, type,
	logic, decision_strategy, owner, ordinal`

// CreatePolicy assigns the ordinal from the resource server's own maximum, the
// way CreateScope and CreateResource do, and writes the config and the three
// association sets in the same transaction so a policy never exists
// half-written.
func (r *authzRepo) CreatePolicy(ctx context.Context, p *model.AuthzPolicy) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`INSERT INTO authz_policy
		   (id, resource_server_id, name, description, type, logic, decision_strategy, owner, ordinal)
		 SELECT $1, $2, $3, $4, $5, $6, $7, $8, COALESCE(MAX(ordinal), -1) + 1
		 FROM authz_policy WHERE resource_server_id = $9`,
		p.ID, p.ClientID, p.Name, p.Description, p.Type, p.Logic, p.DecisionStrategy,
		p.Owner, p.ClientID); err != nil {
		return classify(err)
	}
	if err := insertAuthzPolicyChildren(ctx, tx, p); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

// UpdatePolicy leaves the ordinal alone, so a row the import merges into keeps
// the position its create gave it in GET .../settings.
func (r *authzRepo) UpdatePolicy(ctx context.Context, p *model.AuthzPolicy) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE authz_policy
		    SET name = $1, description = $2, type = $3, logic = $4, decision_strategy = $5, owner = $6
		  WHERE id = $7 AND resource_server_id = $8`,
		p.Name, p.Description, p.Type, p.Logic, p.DecisionStrategy, p.Owner, p.ID, p.ClientID)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	for _, table := range []string{"authz_policy_config", "authz_policy_association"} {
		if _, err := tx.Exec(ctx,
			`DELETE FROM `+table+` WHERE policy_id = $1`, p.ID); err != nil {
			return classify(err)
		}
	}
	if err := insertAuthzPolicyChildren(ctx, tx, p); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

func (r *authzRepo) PolicyByID(ctx context.Context, clientID, policyID string) (*model.AuthzPolicy, error) {
	return r.oneAuthzPolicy(ctx, r.pool.QueryRow(ctx,
		`SELECT `+authzPolicyColumns+` FROM authz_policy
		 WHERE id = $1 AND resource_server_id = $2`, policyID, clientID))
}

func (r *authzRepo) PolicyByName(ctx context.Context, clientID, name string) (*model.AuthzPolicy, error) {
	return r.oneAuthzPolicy(ctx, r.pool.QueryRow(ctx,
		`SELECT `+authzPolicyColumns+` FROM authz_policy
		 WHERE resource_server_id = $1 AND name = $2`, clientID, name))
}

// ListPolicies orders by ordinal, which is creation order. Both listings' name
// sort and the export's partition are applied above this layer; see
// store.AuthzRepo.
func (r *authzRepo) ListPolicies(ctx context.Context, clientID string) ([]*model.AuthzPolicy, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+authzPolicyColumns+` FROM authz_policy
		 WHERE resource_server_id = $1 ORDER BY ordinal`, clientID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectAuthzPolicies(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadAuthzPolicyChildren(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *authzRepo) oneAuthzPolicy(ctx context.Context, row pgx.Row) (*model.AuthzPolicy, error) {
	p := &model.AuthzPolicy{}
	if err := row.Scan(&p.ID, &p.ClientID, &p.Name, &p.Description, &p.Type,
		&p.Logic, &p.DecisionStrategy, &p.Owner, &p.Ordinal); err != nil {
		return nil, classify(err)
	}
	if err := r.loadAuthzPolicyChildren(ctx, []*model.AuthzPolicy{p}); err != nil {
		return nil, err
	}
	return p, nil
}

func collectAuthzPolicies(rows pgx.Rows) ([]*model.AuthzPolicy, error) {
	defer rows.Close()
	out := []*model.AuthzPolicy{}
	for rows.Next() {
		p := &model.AuthzPolicy{}
		if err := rows.Scan(&p.ID, &p.ClientID, &p.Name, &p.Description, &p.Type,
			&p.Logic, &p.DecisionStrategy, &p.Owner, &p.Ordinal); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, classify(rows.Err())
}

func insertAuthzPolicyChildren(ctx context.Context, tx pgx.Tx, p *model.AuthzPolicy) error {
	for i, c := range p.Config {
		if _, err := tx.Exec(ctx,
			`INSERT INTO authz_policy_config (policy_id, name, value, ordinal) VALUES ($1, $2, $3, $4)`,
			p.ID, c.Name, c.Value, i); err != nil {
			return err
		}
	}
	for _, kind := range model.AuthzPolicyAssociationKinds {
		for i, target := range p.AssociationSet(kind) {
			if _, err := tx.Exec(ctx,
				`INSERT INTO authz_policy_association (policy_id, kind, target_id, ordinal)
				 VALUES ($1, $2, $3, $4)`, p.ID, kind, target, i); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadAuthzPolicyChildren fills Config and the three association sets on
// policies already scanned, one query each for the whole set -
// loadAuthzResourceChildren's shape.
func (r *authzRepo) loadAuthzPolicyChildren(ctx context.Context, list []*model.AuthzPolicy) error {
	if len(list) == 0 {
		return nil
	}
	byID := make(map[string]*model.AuthzPolicy, len(list))
	ids := make([]any, 0, len(list))
	placeholders := make([]string, 0, len(list))
	for i, p := range list {
		byID[p.ID] = p
		ids = append(ids, p.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
	}
	in := strings.Join(placeholders, ",")

	rows, err := r.pool.Query(ctx,
		`SELECT policy_id, name, value FROM authz_policy_config
		  WHERE policy_id IN (`+in+`) ORDER BY policy_id, ordinal`, ids...)
	if err != nil {
		return classify(err)
	}
	if err := func() error {
		defer rows.Close()
		for rows.Next() {
			var policyID, name, value string
			if err := rows.Scan(&policyID, &name, &value); err != nil {
				return err
			}
			p := byID[policyID]
			p.Config = append(p.Config, model.AuthzPolicyConfig{Name: name, Value: value})
		}
		return classify(rows.Err())
	}(); err != nil {
		return err
	}

	rows, err = r.pool.Query(ctx,
		`SELECT policy_id, kind, target_id FROM authz_policy_association
		  WHERE policy_id IN (`+in+`) ORDER BY policy_id, kind, ordinal`, ids...)
	if err != nil {
		return classify(err)
	}
	defer rows.Close()
	for rows.Next() {
		var policyID, kind, target string
		if err := rows.Scan(&policyID, &kind, &target); err != nil {
			return err
		}
		byID[policyID].AddAssociation(kind, target)
	}
	return classify(rows.Err())
}

type identityProviderRepo struct{ pool *pgxpool.Pool }

// identityProviderColumns is the SELECT list shared by ByAlias and List, so the
// two cannot come to scan different columns into the same scanner.
const identityProviderColumns = `internal_id, realm_id, alias, display_name, provider_id,
	enabled, trust_email, store_token, add_read_token_role_on_create,
	authenticate_by_default, link_only, hide_on_login, first_broker_login_flow_alias,
	organization_id`

func (r *identityProviderRepo) Create(ctx context.Context, m *model.IdentityProvider) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`INSERT INTO identity_provider
		   (internal_id, realm_id, alias, display_name, provider_id, enabled,
		    trust_email, store_token, add_read_token_role_on_create,
		    authenticate_by_default, link_only, hide_on_login,
		    first_broker_login_flow_alias, organization_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		m.InternalID, m.RealmID, m.Alias, m.DisplayName, m.ProviderID,
		boolToInt(m.Enabled), nullableBool(m.TrustEmail), nullableBool(m.StoreToken),
		nullableBool(m.AddReadTokenRoleOnCreate), nullableBool(m.AuthenticateByDefault),
		nullableBool(m.LinkOnly), nullableBool(m.HideOnLogin),
		m.FirstBrokerLoginFlowAlias, nullableString(m.OrganizationID)); err != nil {
		return classify(err)
	}
	if err := insertIdentityProviderConfig(ctx, tx, m); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

// Update writes every column back, the alias included - see
// store.IdentityProviderRepo for why that is not the organization's rule.
//
// **organization_id is not in the statement**, and that is measured: a PUT
// replaces everything else - a body naming only the alias and the provider id
// emptied a four-key config - and the association survived it, so a `PUT` on an
// associated provider must not clear the column. `POST` and `PUT` do write it,
// through the body's own `organizationId`, and that goes through
// SetOrganization rather than here so that the one write has one place.
func (r *identityProviderRepo) Update(ctx context.Context, m *model.IdentityProvider) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE identity_provider
		    SET alias = $1, display_name = $2, provider_id = $3, enabled = $4,
		        trust_email = $5, store_token = $6, add_read_token_role_on_create = $7,
		        authenticate_by_default = $8, link_only = $9, hide_on_login = $10,
		        first_broker_login_flow_alias = $11
		  WHERE internal_id = $12`,
		m.Alias, m.DisplayName, m.ProviderID, boolToInt(m.Enabled),
		nullableBool(m.TrustEmail), nullableBool(m.StoreToken),
		nullableBool(m.AddReadTokenRoleOnCreate), nullableBool(m.AuthenticateByDefault),
		nullableBool(m.LinkOnly), nullableBool(m.HideOnLogin),
		m.FirstBrokerLoginFlowAlias, m.InternalID)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM identity_provider_config WHERE internal_id = $1`, m.InternalID); err != nil {
		return classify(err)
	}
	if err := insertIdentityProviderConfig(ctx, tx, m); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

func (r *identityProviderRepo) Delete(ctx context.Context, realmID, alias string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM identity_provider WHERE realm_id = $1 AND alias = $2`, realmID, alias)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (r *identityProviderRepo) ByAlias(ctx context.Context, realmID, alias string) (*model.IdentityProvider, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+identityProviderColumns+` FROM identity_provider
		  WHERE realm_id = $1 AND alias = $2`, realmID, alias)
	m, err := scanIdentityProvider(row)
	if err != nil {
		return nil, err
	}
	if err := r.loadIdentityProviderConfig(ctx, []*model.IdentityProvider{m}); err != nil {
		return nil, err
	}
	return m, nil
}

// List orders by alias, which is the measured serving order. A row whose alias
// was cleared sorts first, which is where the server puts it too - NULLS FIRST
// is spelled out because Postgres sorts NULLs last by default and SQLite sorts
// them first, and this is exactly the kind of place the two drivers would
// otherwise diverge without anything failing to compile.
func (r *identityProviderRepo) List(ctx context.Context, realmID string) ([]*model.IdentityProvider, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+identityProviderColumns+` FROM identity_provider
		  WHERE realm_id = $1 ORDER BY alias NULLS FIRST`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectIdentityProviders(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadIdentityProviderConfig(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListByOrganization filters List's rows rather than joining a second table,
// because the association is a column on this one.
func (r *identityProviderRepo) ListByOrganization(ctx context.Context, realmID, orgID string) ([]*model.IdentityProvider, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+identityProviderColumns+` FROM identity_provider
		  WHERE realm_id = $1 AND organization_id = $2 ORDER BY alias NULLS FIRST`,
		realmID, orgID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectIdentityProviders(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadIdentityProviderConfig(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// SetOrganization writes the association, or clears it when orgID is empty.
func (r *identityProviderRepo) SetOrganization(ctx context.Context, realmID, alias, orgID string) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE identity_provider SET organization_id = $1
		  WHERE realm_id = $2 AND alias = $3`, nullableString(orgID), realmID, alias)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func insertIdentityProviderConfig(ctx context.Context, tx pgx.Tx, m *model.IdentityProvider) error {
	for i, e := range m.Config {
		if _, err := tx.Exec(ctx,
			`INSERT INTO identity_provider_config (internal_id, name, value, ordinal)
			 VALUES ($1, $2, $3, $4)`, m.InternalID, e.Name, e.Value, i); err != nil {
			return err
		}
	}
	return nil
}

func (r *identityProviderRepo) loadIdentityProviderConfig(ctx context.Context, ps []*model.IdentityProvider) error {
	if len(ps) == 0 {
		return nil
	}
	byID := make(map[string]*model.IdentityProvider, len(ps))
	ids := make([]any, 0, len(ps))
	placeholders := make([]string, 0, len(ps))
	for i, p := range ps {
		byID[p.InternalID] = p
		ids = append(ids, p.InternalID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
	}
	rows, err := r.pool.Query(ctx,
		`SELECT internal_id, name, value FROM identity_provider_config
		  WHERE internal_id IN (`+strings.Join(placeholders, ",")+`)
		  ORDER BY internal_id, ordinal`, ids...)
	if err != nil {
		return classify(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name, value string
		if err := rows.Scan(&id, &name, &value); err != nil {
			return err
		}
		p := byID[id]
		p.Config = append(p.Config, model.IdentityProviderConfigEntry{Name: name, Value: value})
	}
	return classify(rows.Err())
}

func collectIdentityProviders(rows pgx.Rows) ([]*model.IdentityProvider, error) {
	defer rows.Close()
	out := []*model.IdentityProvider{}
	for rows.Next() {
		m, err := scanIdentityProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

func scanIdentityProvider(row scanner) (*model.IdentityProvider, error) {
	m := &model.IdentityProvider{}
	var alias, organizationID *string
	var enabled int
	var trustEmail, storeToken, addReadToken, authByDefault, linkOnly, hideOnLogin *int64
	if err := row.Scan(&m.InternalID, &m.RealmID, &alias, &m.DisplayName, &m.ProviderID,
		&enabled, &trustEmail, &storeToken, &addReadToken, &authByDefault,
		&linkOnly, &hideOnLogin, &m.FirstBrokerLoginFlowAlias, &organizationID); err != nil {
		return nil, classify(err)
	}
	m.Alias = alias
	if organizationID != nil {
		m.OrganizationID = *organizationID
	}
	m.Enabled = enabled != 0
	m.TrustEmail = boolFromNull(trustEmail)
	m.StoreToken = boolFromNull(storeToken)
	m.AddReadTokenRoleOnCreate = boolFromNull(addReadToken)
	m.AuthenticateByDefault = boolFromNull(authByDefault)
	m.LinkOnly = boolFromNull(linkOnly)
	m.HideOnLogin = boolFromNull(hideOnLogin)
	return m, nil
}

// nullableBool and boolFromNull carry the tri-state the six flag columns need.
// They are two functions rather than one generic helper because the driver
// boundary is where absent stops being a pointer and starts being a NULL, and
// naming both directions is what makes the round trip readable.
func nullableBool(b *bool) any {
	if b == nil {
		return nil
	}
	return boolToInt(*b)
}

func boolFromNull(n *int64) *bool {
	if n == nil {
		return nil
	}
	v := *n != 0
	return &v
}

// nullableString writes "" as NULL. It exists for identity_provider's
// organization_id, whose two states on the wire are "carries the key" and "has
// no such key" - there is no third, so the empty string and NULL do not need
// telling apart, and a NULL is what makes `WHERE organization_id = $2` select
// nothing for an unassociated provider rather than everything unassociated.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

type componentRepo struct{ pool *pgxpool.Pool }

const componentColumns = `id, realm_id, name, provider_id, provider_type, parent_id, sub_type`

func (r *componentRepo) Create(ctx context.Context, m *model.Component) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var ordinal int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(ordinal), -1) + 1 FROM component WHERE realm_id = $1`,
		m.RealmID).Scan(&ordinal); err != nil {
		return classify(err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO component
		   (id, realm_id, name, provider_id, provider_type, parent_id, sub_type, ordinal)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		m.ID, m.RealmID, m.Name, m.ProviderID, m.ProviderType, m.ParentID,
		m.SubType, ordinal); err != nil {
		return classify(err)
	}
	// The values are flattened with a compound ordinal so that a name holding
	// several values keeps both its position among the names and the order of
	// its own values - organization_attribute's arithmetic, for the same
	// reason.
	for i, e := range m.Config {
		for j, v := range e.Values {
			if _, err := tx.Exec(ctx,
				`INSERT INTO component_config (component_id, name, value, ordinal)
				 VALUES ($1, $2, $3, $4)`, m.ID, e.Name, v, i*1000+j); err != nil {
				return classify(err)
			}
		}
	}
	return tx.Commit(ctx)
}

// Update replaces the row and rewrites its whole config. The config arrives
// already merged and already filtered - internal/admin owns both, because both
// need the provider catalogue - so this deletes and reinserts rather than
// diffing, which is also what keeps the ordinals contiguous.
//
// The row's `ordinal` is left alone, so an updated component keeps its place in
// the listing. Nothing measured says it should move and nothing measured says
// it should not; leaving it is the smaller claim.
func (r *componentRepo) Update(ctx context.Context, m *model.Component) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE component
		    SET name = $1, provider_id = $2, provider_type = $3, parent_id = $4, sub_type = $5
		  WHERE realm_id = $6 AND id = $7`,
		m.Name, m.ProviderID, m.ProviderType, m.ParentID, m.SubType, m.RealmID, m.ID)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM component_config WHERE component_id = $1`, m.ID); err != nil {
		return classify(err)
	}
	for i, e := range m.Config {
		for j, v := range e.Values {
			if _, err := tx.Exec(ctx,
				`INSERT INTO component_config (component_id, name, value, ordinal)
				 VALUES ($1, $2, $3, $4)`, m.ID, e.Name, v, i*1000+j); err != nil {
				return classify(err)
			}
		}
	}
	return tx.Commit(ctx)
}

func (r *componentRepo) Delete(ctx context.Context, realmID, id string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM component WHERE realm_id = $1 AND id = $2`, realmID, id)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (r *componentRepo) ByID(ctx context.Context, realmID, id string) (*model.Component, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+componentColumns+` FROM component WHERE realm_id = $1 AND id = $2`,
		realmID, id)
	m, err := scanComponent(row)
	if err != nil {
		return nil, err
	}
	if err := r.loadComponentConfig(ctx, []*model.Component{m}); err != nil {
		return nil, err
	}
	return m, nil
}

func (r *componentRepo) List(ctx context.Context, realmID string) ([]*model.Component, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+componentColumns+` FROM component WHERE realm_id = $1 ORDER BY ordinal`,
		realmID)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectComponents(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadComponentConfig(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *componentRepo) loadComponentConfig(ctx context.Context, cs []*model.Component) error {
	if len(cs) == 0 {
		return nil
	}
	byID := make(map[string]*model.Component, len(cs))
	ids := make([]any, 0, len(cs))
	placeholders := make([]string, 0, len(cs))
	for i, c := range cs {
		byID[c.ID] = c
		ids = append(ids, c.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
	}
	rows, err := r.pool.Query(ctx,
		`SELECT component_id, name, value FROM component_config
		  WHERE component_id IN (`+strings.Join(placeholders, ",")+`)
		  ORDER BY component_id, ordinal`, ids...)
	if err != nil {
		return classify(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name, value string
		if err := rows.Scan(&id, &name, &value); err != nil {
			return err
		}
		byID[id].AddConfig(name, value)
	}
	return classify(rows.Err())
}

func collectComponents(rows pgx.Rows) ([]*model.Component, error) {
	defer rows.Close()
	out := []*model.Component{}
	for rows.Next() {
		m, err := scanComponent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

func scanComponent(row scanner) (*model.Component, error) {
	m := &model.Component{}
	var name *string
	if err := row.Scan(&m.ID, &m.RealmID, &name, &m.ProviderID, &m.ProviderType,
		&m.ParentID, &m.SubType); err != nil {
		return nil, classify(err)
	}
	m.Name = name
	return m, nil
}

type identityProviderMapperRepo struct{ pool *pgxpool.Pool }

// identityProviderMapperColumns is the SELECT list shared by ByID and List, so
// the two cannot come to scan different columns into one scanner.
const identityProviderMapperColumns = `id, realm_id, alias, name, mapper`

func (r *identityProviderMapperRepo) Create(ctx context.Context, m *model.IdentityProviderMapper) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var ordinal int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(ordinal), -1) + 1 FROM identity_provider_mapper
		  WHERE realm_id = $1 AND alias = $2`, m.RealmID, m.Alias).Scan(&ordinal); err != nil {
		return classify(err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO identity_provider_mapper (id, realm_id, alias, name, mapper, ordinal)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		m.ID, m.RealmID, m.Alias, m.Name, m.Mapper, ordinal); err != nil {
		return classify(err)
	}
	for i, e := range m.Config {
		if _, err := tx.Exec(ctx,
			`INSERT INTO identity_provider_mapper_config (mapper_id, name, value, ordinal)
			 VALUES ($1, $2, $3, $4)`, m.ID, e.Name, e.Value, i); err != nil {
			return classify(err)
		}
	}
	return tx.Commit(ctx)
}

// Update replaces every column and the whole config - see
// store.IdentityProviderMapperRepo, and note that this is the opposite of what
// PUT /components/{id} does one chapter away.
//
// It is keyed on the id alone, because the mapper the route writes is the one
// the **body's** id names and the path's alias is not consulted.
func (r *identityProviderMapperRepo) Update(ctx context.Context, m *model.IdentityProviderMapper) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE identity_provider_mapper SET alias = $1, name = $2, mapper = $3
		  WHERE realm_id = $4 AND id = $5`,
		m.Alias, m.Name, m.Mapper, m.RealmID, m.ID)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM identity_provider_mapper_config WHERE mapper_id = $1`, m.ID); err != nil {
		return classify(err)
	}
	for i, e := range m.Config {
		if _, err := tx.Exec(ctx,
			`INSERT INTO identity_provider_mapper_config (mapper_id, name, value, ordinal)
			 VALUES ($1, $2, $3, $4)`, m.ID, e.Name, e.Value, i); err != nil {
			return classify(err)
		}
	}
	return tx.Commit(ctx)
}

func (r *identityProviderMapperRepo) ByID(ctx context.Context, realmID, id string) (*model.IdentityProviderMapper, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+identityProviderMapperColumns+` FROM identity_provider_mapper
		  WHERE realm_id = $1 AND id = $2`, realmID, id)
	m, err := scanIdentityProviderMapper(row)
	if err != nil {
		return nil, err
	}
	if err := r.loadIdentityProviderMapperConfig(ctx, []*model.IdentityProviderMapper{m}); err != nil {
		return nil, err
	}
	return m, nil
}

func (r *identityProviderMapperRepo) Delete(ctx context.Context, realmID, id string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM identity_provider_mapper WHERE realm_id = $1 AND id = $2`, realmID, id)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (r *identityProviderMapperRepo) List(ctx context.Context, realmID, alias string) ([]*model.IdentityProviderMapper, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+identityProviderMapperColumns+` FROM identity_provider_mapper
		  WHERE realm_id = $1 AND alias = $2 ORDER BY ordinal`, realmID, alias)
	if err != nil {
		return nil, classify(err)
	}
	out, err := collectIdentityProviderMappers(rows)
	if err != nil {
		return nil, err
	}
	if err := r.loadIdentityProviderMapperConfig(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *identityProviderMapperRepo) loadIdentityProviderMapperConfig(ctx context.Context, ms []*model.IdentityProviderMapper) error {
	if len(ms) == 0 {
		return nil
	}
	byID := make(map[string]*model.IdentityProviderMapper, len(ms))
	ids := make([]any, 0, len(ms))
	placeholders := make([]string, 0, len(ms))
	for i, m := range ms {
		byID[m.ID] = m
		ids = append(ids, m.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
	}
	rows, err := r.pool.Query(ctx,
		`SELECT mapper_id, name, value FROM identity_provider_mapper_config
		  WHERE mapper_id IN (`+strings.Join(placeholders, ",")+`)
		  ORDER BY mapper_id, ordinal`, ids...)
	if err != nil {
		return classify(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name, value string
		if err := rows.Scan(&id, &name, &value); err != nil {
			return err
		}
		m := byID[id]
		m.Config = append(m.Config, model.IdentityProviderMapperConfigEntry{Name: name, Value: value})
	}
	return classify(rows.Err())
}

func collectIdentityProviderMappers(rows pgx.Rows) ([]*model.IdentityProviderMapper, error) {
	defer rows.Close()
	out := []*model.IdentityProviderMapper{}
	for rows.Next() {
		m, err := scanIdentityProviderMapper(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

func scanIdentityProviderMapper(row scanner) (*model.IdentityProviderMapper, error) {
	m := &model.IdentityProviderMapper{}
	if err := row.Scan(&m.ID, &m.RealmID, &m.Alias, &m.Name, &m.Mapper); err != nil {
		return nil, classify(err)
	}
	return m, nil
}

type localizationRepo struct{ pool *pgxpool.Pool }

func (r *localizationRepo) Locales(ctx context.Context, realmID string) ([]string, error) {
	// ORDER BY locale is the measurement, not tidiness: five locales inserted
	// zz, aa, mm, ru, de-CH came back aa, de-CH, mm, ru, zz.
	rows, err := r.pool.Query(ctx,
		`SELECT locale FROM realm_localization WHERE realm_id = $1 ORDER BY locale`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var locale string
		if err := rows.Scan(&locale); err != nil {
			return nil, err
		}
		out = append(out, locale)
	}
	return out, classify(rows.Err())
}

func (r *localizationRepo) ByLocale(ctx context.Context, realmID, locale string) (*model.LocalizationTexts, error) {
	var column *string
	if err := r.pool.QueryRow(ctx,
		`SELECT texts FROM realm_localization WHERE realm_id = $1 AND locale = $2`,
		realmID, locale).Scan(&column); err != nil {
		return nil, classify(err)
	}
	return store.DecodeLocalizationTexts(locale, column)
}

func (r *localizationRepo) Put(ctx context.Context, realmID string, t *model.LocalizationTexts) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO realm_localization (realm_id, locale, texts) VALUES ($1, $2, $3)
		 ON CONFLICT (realm_id, locale) DO UPDATE SET texts = excluded.texts`,
		realmID, t.Locale, store.EncodeLocalizationTexts(t))
	return classify(err)
}

func (r *localizationRepo) DeleteLocale(ctx context.Context, realmID, locale string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM realm_localization WHERE realm_id = $1 AND locale = $2`, realmID, locale)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

type clientInitialAccessRepo struct{ pool *pgxpool.Pool }

// clientInitialAccessColumns is the SELECT list, so List cannot come to scan a
// different set from what a future single-row read would.
const clientInitialAccessColumns = `id, realm_id, created_timestamp, expiration, total_count, remaining_count`

func (r *clientInitialAccessRepo) Create(ctx context.Context, m *model.ClientInitialAccess) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var ordinal int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(ordinal), -1) + 1 FROM client_initial_access WHERE realm_id = $1`,
		m.RealmID).Scan(&ordinal); err != nil {
		return classify(err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO client_initial_access
		   (id, realm_id, created_timestamp, expiration, total_count, remaining_count, ordinal)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		m.ID, m.RealmID, m.Timestamp, m.Expiration, m.Count, m.RemainingCount,
		ordinal); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

func (r *clientInitialAccessRepo) List(ctx context.Context, realmID string) ([]*model.ClientInitialAccess, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+clientInitialAccessColumns+`
		   FROM client_initial_access WHERE realm_id = $1 ORDER BY ordinal`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []*model.ClientInitialAccess{}
	for rows.Next() {
		m, err := scanClientInitialAccess(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

// Delete swallows a missing row on purpose: the endpoint answers 204 for an id
// that never existed and for one deleted twice, both measured.
func (r *clientInitialAccessRepo) Delete(ctx context.Context, realmID, id string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM client_initial_access WHERE realm_id = $1 AND id = $2`, realmID, id)
	return classify(err)
}

func scanClientInitialAccess(row scanner) (*model.ClientInitialAccess, error) {
	m := &model.ClientInitialAccess{}
	if err := row.Scan(&m.ID, &m.RealmID, &m.Timestamp, &m.Expiration, &m.Count,
		&m.RemainingCount); err != nil {
		return nil, classify(err)
	}
	return m, nil
}

type authenticationFlowRepo struct{ pool *pgxpool.Pool }

// The three SELECT lists are spelled once each, so a list method and a
// single-row read cannot come to scan a different set of columns into the one
// scan helper below them.
const (
	authenticationFlowColumns      = `id, realm_id, alias, description, provider_id, top_level, built_in, ordinal`
	authenticationExecutionColumns = `id, realm_id, parent_flow_id, authenticator, flow_id, config_id, requirement, priority`
	authenticationConfigColumns    = `id, realm_id, alias, config`
)

// ListFlows serves every flow of the realm, sub-flows included. Filtering the
// top-level ones out is GET /flows' job and is done in internal/admin, because
// the execution walk needs the rest.
func (r *authenticationFlowRepo) ListFlows(ctx context.Context, realmID string) ([]*model.AuthenticationFlow, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+authenticationFlowColumns+` FROM authentication_flow
		  WHERE realm_id = $1 ORDER BY ordinal`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	return collectAuthenticationFlows(rows)
}

func (r *authenticationFlowRepo) FlowByID(ctx context.Context, realmID, id string) (*model.AuthenticationFlow, error) {
	return scanAuthenticationFlow(r.pool.QueryRow(ctx,
		`SELECT `+authenticationFlowColumns+` FROM authentication_flow
		  WHERE realm_id = $1 AND id = $2`, realmID, id))
}

// FlowByAlias cannot reach a flow whose alias is NULL, and that is the measured
// consequence rather than a gap: `alias = $2` is never true of a NULL, so the
// aliasless flow POST /flows/{alias}/copy creates stays addressable by id
// alone.
func (r *authenticationFlowRepo) FlowByAlias(ctx context.Context, realmID, alias string) (*model.AuthenticationFlow, error) {
	return scanAuthenticationFlow(r.pool.QueryRow(ctx,
		`SELECT `+authenticationFlowColumns+` FROM authentication_flow
		  WHERE realm_id = $1 AND alias = $2`, realmID, alias))
}

// CreateFlow numbers the row itself - the component and client_initial_access
// device - because GET /flows is insertion-ordered and the ids are random
// UUIDs that do not sort that way. The caller's Ordinal is not read, so a seed
// that inserts in order gets that order back whatever it left in the field.
func (r *authenticationFlowRepo) CreateFlow(ctx context.Context, f *model.AuthenticationFlow) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var ordinal int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(ordinal), -1) + 1 FROM authentication_flow WHERE realm_id = $1`,
		f.RealmID).Scan(&ordinal); err != nil {
		return classify(err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO authentication_flow (`+authenticationFlowColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		f.ID, f.RealmID, f.Alias, f.Description, f.ProviderID,
		boolToInt(f.TopLevel), boolToInt(f.BuiltIn), ordinal); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

// UpdateFlow leaves `ordinal` alone, so a renamed flow keeps its place in the
// listing. It does not consult built_in either: a built-in flow can be renamed
// through PUT /flows/{id}, measured.
func (r *authenticationFlowRepo) UpdateFlow(ctx context.Context, f *model.AuthenticationFlow) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE authentication_flow
		    SET alias = $1, description = $2, provider_id = $3, top_level = $4, built_in = $5
		  WHERE realm_id = $6 AND id = $7`,
		f.Alias, f.Description, f.ProviderID, boolToInt(f.TopLevel),
		boolToInt(f.BuiltIn), f.RealmID, f.ID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

// DeleteFlow takes the flow's execution rows with it by cascade. Refusing a
// built-in flow is a 400 with a body and belongs to internal/admin.
func (r *authenticationFlowRepo) DeleteFlow(ctx context.Context, realmID, id string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM authentication_flow WHERE realm_id = $1 AND id = $2`, realmID, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

// ListExecutions serves one parent's direct rows. The tie-break on id is there
// so two rows sharing a priority - which nothing forbids - come back in the
// same order from both drivers, since storetest is the only evidence they
// agree.
func (r *authenticationFlowRepo) ListExecutions(ctx context.Context, realmID, parentFlowID string) ([]*model.AuthenticationExecution, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+authenticationExecutionColumns+` FROM authentication_execution
		  WHERE realm_id = $1 AND parent_flow_id = $2 ORDER BY priority, id`,
		realmID, parentFlowID)
	if err != nil {
		return nil, classify(err)
	}
	return collectAuthenticationExecutions(rows)
}

func (r *authenticationFlowRepo) ExecutionByID(ctx context.Context, realmID, id string) (*model.AuthenticationExecution, error) {
	return scanAuthenticationExecution(r.pool.QueryRow(ctx,
		`SELECT `+authenticationExecutionColumns+` FROM authentication_execution
		  WHERE realm_id = $1 AND id = $2`, realmID, id))
}

func (r *authenticationFlowRepo) CreateExecution(ctx context.Context, e *model.AuthenticationExecution) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO authentication_execution (`+authenticationExecutionColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		e.ID, e.RealmID, e.ParentFlowID, nullableString(e.Authenticator),
		nullableString(e.FlowID), nullableString(e.ConfigID), e.Requirement, e.Priority)
	return classify(err)
}

// UpdateExecution writes the three columns a route moves - the requirement, the
// priority the two swaps exchange, and the config pointer POST
// /executions/{id}/config repoints. The parent, the authenticator and the
// sub-flow are not among them.
func (r *authenticationFlowRepo) UpdateExecution(ctx context.Context, e *model.AuthenticationExecution) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE authentication_execution SET requirement = $1, priority = $2, config_id = $3
		  WHERE realm_id = $4 AND id = $5`,
		e.Requirement, e.Priority, nullableString(e.ConfigID), e.RealmID, e.ID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

func (r *authenticationFlowRepo) DeleteExecution(ctx context.Context, realmID, id string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM authentication_execution WHERE realm_id = $1 AND id = $2`, realmID, id)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

// ListConfigs orders by id, because authentication_config carries no ordinal:
// no route lists these, so nothing measured constrains the order and a stable
// one is all the two drivers need in order to agree.
func (r *authenticationFlowRepo) ListConfigs(ctx context.Context, realmID string) ([]*model.AuthenticationConfig, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+authenticationConfigColumns+` FROM authentication_config
		  WHERE realm_id = $1 ORDER BY id`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	return collectAuthenticationConfigs(rows)
}

func (r *authenticationFlowRepo) ConfigByID(ctx context.Context, realmID, id string) (*model.AuthenticationConfig, error) {
	return scanAuthenticationConfig(r.pool.QueryRow(ctx,
		`SELECT `+authenticationConfigColumns+` FROM authentication_config
		  WHERE realm_id = $1 AND id = $2`, realmID, id))
}

func (r *authenticationFlowRepo) CreateConfig(ctx context.Context, c *model.AuthenticationConfig) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO authentication_config (`+authenticationConfigColumns+`)
		 VALUES ($1, $2, $3, $4)`,
		c.ID, c.RealmID, c.Alias, encode(c.Config))
	return classify(err)
}

func (r *authenticationFlowRepo) UpdateConfig(ctx context.Context, c *model.AuthenticationConfig) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE authentication_config SET alias = $1, config = $2
		  WHERE realm_id = $3 AND id = $4`,
		c.Alias, encode(c.Config), c.RealmID, c.ID)
	if err != nil {
		return classify(err)
	}
	return affectedOne(tag.RowsAffected())
}

// DeleteConfig removes the config and clears every execution of the realm
// pointing at it, in one transaction. config_id carries no foreign key on
// purpose - the execution stays addressable - so the clearing is a statement
// here rather than a cascade, and it is here rather than in internal/admin so
// that both drivers do it.
func (r *authenticationFlowRepo) DeleteConfig(ctx context.Context, realmID, id string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`DELETE FROM authentication_config WHERE realm_id = $1 AND id = $2`, realmID, id)
	if err != nil {
		return classify(err)
	}
	if err := affectedOne(tag.RowsAffected()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE authentication_execution SET config_id = NULL
		  WHERE realm_id = $1 AND config_id = $2`, realmID, id); err != nil {
		return classify(err)
	}
	return tx.Commit(ctx)
}

func scanAuthenticationFlow(row scanner) (*model.AuthenticationFlow, error) {
	m := &model.AuthenticationFlow{}
	var alias *string
	var topLevel, builtIn int
	if err := row.Scan(&m.ID, &m.RealmID, &alias, &m.Description, &m.ProviderID,
		&topLevel, &builtIn, &m.Ordinal); err != nil {
		return nil, classify(err)
	}
	m.Alias = alias
	m.TopLevel = topLevel != 0
	m.BuiltIn = builtIn != 0
	return m, nil
}

func collectAuthenticationFlows(rows pgx.Rows) ([]*model.AuthenticationFlow, error) {
	defer rows.Close()
	out := []*model.AuthenticationFlow{}
	for rows.Next() {
		m, err := scanAuthenticationFlow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

// scanAuthenticationExecution reads the three nullable text columns back as the
// empty string, which is the same round trip nullableString writes: the wire
// has no third state between "absent" and "empty" on any of them.
func scanAuthenticationExecution(row scanner) (*model.AuthenticationExecution, error) {
	m := &model.AuthenticationExecution{}
	var authenticator, flowID, configID *string
	if err := row.Scan(&m.ID, &m.RealmID, &m.ParentFlowID, &authenticator,
		&flowID, &configID, &m.Requirement, &m.Priority); err != nil {
		return nil, classify(err)
	}
	m.Authenticator = derefString(authenticator)
	m.FlowID = derefString(flowID)
	m.ConfigID = derefString(configID)
	return m, nil
}

// derefString is nullableString's other direction: a NULL comes back as "".
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func collectAuthenticationExecutions(rows pgx.Rows) ([]*model.AuthenticationExecution, error) {
	defer rows.Close()
	out := []*model.AuthenticationExecution{}
	for rows.Next() {
		m, err := scanAuthenticationExecution(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

func scanAuthenticationConfig(row scanner) (*model.AuthenticationConfig, error) {
	m := &model.AuthenticationConfig{}
	var config string
	if err := row.Scan(&m.ID, &m.RealmID, &m.Alias, &config); err != nil {
		return nil, classify(err)
	}
	if err := decode(config, &m.Config); err != nil {
		return nil, err
	}
	return m, nil
}

func collectAuthenticationConfigs(rows pgx.Rows) ([]*model.AuthenticationConfig, error) {
	defer rows.Close()
	out := []*model.AuthenticationConfig{}
	for rows.Next() {
		m, err := scanAuthenticationConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

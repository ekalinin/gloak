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
	Organizations() OrganizationRepo
	Authz() AuthzRepo
	IdentityProviders() IdentityProviderRepo
	IdentityProviderMappers() IdentityProviderMapperRepo
	Components() ComponentRepo
	Localizations() LocalizationRepo
	ClientInitialAccess() ClientInitialAccessRepo
	Close() error
}

// ClientInitialAccessRepo stores a realm's initial access tokens.
//
// **There is no Update and no ByID**, and both absences are measured. Nothing
// in the Admin API reads one row - `GET /clients-initial-access` is the
// collection and there is no single-row route - and the only mutation Keycloak
// has is the registration endpoint decrementing `remainingCount`, which lives
// in a package this repository's boundary table keeps away from the Admin API.
// A method nothing calls is a claim about the model that is not true.
type ClientInitialAccessRepo interface {
	// Create inserts one row. The token is not stored: it is a JWT whose `jti`
	// is this id, so recognising one is verifying it and looking the id up.
	Create(ctx context.Context, c *model.ClientInitialAccess) error
	// List returns a realm's rows **in insertion order**, which is measured
	// rather than chosen: three rows created in one realm came back in creation
	// order on two container starts and two reads apiece, and their ids are
	// random UUIDs that do not sort that way.
	List(ctx context.Context, realmID string) ([]*model.ClientInitialAccess, error)
	// Delete removes one by id. **It reports no error for an id that is not
	// there**, because the endpoint is a 204 for an id that never existed and
	// for one deleted twice - measured on both.
	Delete(ctx context.Context, realmID, id string) error
}

// LocalizationRepo stores a realm's message bundles, one document per locale.
//
// **It decides nothing about key order.** Which order a write leaves behind is
// a measured Keycloak behaviour that differs per write path - `POST` re-buckets
// the whole document through a Java map and the other three preserve it - and
// putting that behind a SQL boundary would hide a contract from the package
// whose job is to reproduce it. `Put` therefore replaces the document with
// exactly the slice internal/admin computed.
type LocalizationRepo interface {
	// Locales returns the locales the realm has a document for, **sorted**.
	// Measured: five locales inserted `zz, aa, mm, ru, de-CH` came back
	// `aa, de-CH, mm, ru, zz`. A locale whose document is nil is in the list -
	// that is how the empty-body POST's defect is visible at all.
	Locales(ctx context.Context, realmID string) ([]string, error)
	// ByLocale reads one document. ErrNotFound means the realm has no row for
	// that locale, which the read turns into `200 {}` and the delete into a
	// 404 - two answers to one absence, measured on each.
	ByLocale(ctx context.Context, realmID, locale string) (*model.LocalizationTexts, error)
	// Put replaces the whole document, creating the row when there is none.
	// A nil Texts stores the "no document" state that only an empty POST body
	// reaches; see model.LocalizationTexts.
	Put(ctx context.Context, realmID string, t *model.LocalizationTexts) error
	// DeleteLocale removes the row. ErrNotFound becomes
	// `404 {"error":"No localization texts for locale <l> found."}`.
	DeleteLocale(ctx context.Context, realmID, locale string) error
}

// EncodeLocalizationTexts renders a bundle for the drivers' one nullable
// column, and DecodeLocalizationTexts reads it back.
//
// **They live here rather than once per driver because the null is the
// contract.** A nil Texts is the state an empty POST body leaves behind, an
// empty Texts is the state `{}` leaves, and the two answer differently for
// ever after; a copy of this in each driver is a copy that can come to
// disagree about which is which, and the suite would see it only through
// whichever driver a test happened to open. The two drivers already duplicate
// their scanners, and those decode columns that cannot mean two things.
func EncodeLocalizationTexts(t *model.LocalizationTexts) any {
	if t == nil || t.Texts == nil {
		return nil
	}
	b, err := json.Marshal(t.Texts)
	if err != nil {
		// model.LocalizationText holds two strings, so this cannot happen; the
		// same judgement each driver's own encode makes.
		return nil
	}
	return string(b)
}

// DecodeLocalizationTexts turns a column back into a bundle. An invalid column
// is reported rather than smoothed over: nothing but EncodeLocalizationTexts
// writes it, so a value that will not parse is a corrupted row and not a state
// the API can reach.
func DecodeLocalizationTexts(locale string, column *string) (*model.LocalizationTexts, error) {
	t := &model.LocalizationTexts{Locale: locale}
	if column == nil {
		return t, nil
	}
	if err := json.Unmarshal([]byte(*column), &t.Texts); err != nil {
		return nil, err
	}
	// A stored "null" would decode to a nil slice and read as the defect
	// state, so the encoder's two shapes are the only two this returns.
	if t.Texts == nil {
		t.Texts = []model.LocalizationText{}
	}
	return t, nil
}

// IdentityProviderRepo stores a realm's identity providers.
//
// It is deliberately small, OrganizationRepo's precedent: the listing's
// `search`, `first` and `max` all run in internal/admin over what List returns,
// because `search` is a case-insensitive **prefix** with `*` as a wildcard and
// `"quotes"` meaning equality - the user listing's rule and not the four-field
// substring one - and writing that comparison twice is writing it twice.
type IdentityProviderRepo interface {
	// Create inserts the provider and its config. An alias the realm already
	// holds is ErrConflict, which internal/admin turns into the measured
	// `409 {"errorMessage":"Identity Provider a already exists"}`.
	Create(ctx context.Context, p *model.IdentityProvider) error
	// Update **replaces**, alias included. Measured: a provider carrying eight
	// non-default fields and four config keys, updated with a body naming only
	// the alias, the provider id and a display name, kept its internal id and
	// lost everything else. It is keyed on the internal id and not on the alias
	// for exactly that reason - the alias is one of the things it writes, and
	// a PUT whose body has none writes it away.
	Update(ctx context.Context, p *model.IdentityProvider) error
	// Delete removes one by alias. ErrNotFound becomes the generic
	// `404 {"error":"HTTP 404 Not Found"}` and **not** one of the spellings of
	// not-found: this family has none of its own.
	Delete(ctx context.Context, realmID, alias string) error
	// ByAlias resolves the provider every route in the family addresses.
	ByAlias(ctx context.Context, realmID, alias string) (*model.IdentityProvider, error)
	// List returns every provider of one realm **sorted by alias**, which is
	// the measured serving order: three created `zzz, mmm, aaa` came back
	// `aaa, mmm, zzz`. A provider whose alias was cleared sorts first.
	List(ctx context.Context, realmID string) ([]*model.IdentityProvider, error)
	// ListByOrganization returns the providers associated with one
	// organization, in List's order.
	//
	// **An organization's identity providers are a column on the provider, not
	// a join table**, and both directions are measured: associating one makes
	// the *realm's* own read of that provider start carrying
	// `"organizationId"`, and removing the association drops the key and leaves
	// the provider. So this is a filter over the same rows List returns and the
	// two can never disagree about what a provider is.
	ListByOrganization(ctx context.Context, realmID, orgID string) ([]*model.IdentityProvider, error)
	// SetOrganization writes the association, or clears it when orgID is empty.
	// It is keyed on the alias because both routes that call it carry one.
	//
	// It does not refuse a provider that already belongs to another
	// organization: that is a 400 naming neither row, so the handler reads the
	// provider first and this method only writes.
	SetOrganization(ctx context.Context, realmID, alias, orgID string) error
}

// IdentityProviderMapperRepo stores a realm's identity provider mappers.
//
// **Its two lookups are scoped differently and that is measured, not an
// oversight.** List takes the alias in the path and filters by it; ByID does
// not take one at all, because the three single-mapper routes ignore the path's
// alias entirely - a mapper created under one provider was read through a
// second provider's path with a 200 and then deleted through it with a 204,
// while that second provider's own listing stayed empty. Giving ByID an alias
// argument "for symmetry" is the tidy-up that turns two measured 2xx into 404s.
type IdentityProviderMapperRepo interface {
	// Create inserts a mapper and its config. A name the same alias already
	// holds is ErrConflict, which internal/admin turns into the measured
	// `400 {"errorMessage":"Failed to add mapper 'x' to identity provider
	// [oidc]."}` - a 400 rather than the 409 most of this API answers, and a
	// sentence naming the **providerId** where the route carries the alias.
	Create(ctx context.Context, m *model.IdentityProviderMapper) error
	// Update **replaces**, config included: a PUT naming one config key on a
	// mapper holding four left it holding one. That is the opposite of
	// `PUT /components/{id}`, which merges, one chapter away.
	Update(ctx context.Context, m *model.IdentityProviderMapper) error
	// ByID resolves a mapper realm-wide. ErrNotFound becomes
	// `404 {"error":"Model not found"}`, which is a spelling of not-found this
	// API did not previously have.
	ByID(ctx context.Context, realmID, id string) (*model.IdentityProviderMapper, error)
	// Delete removes one by id, realm-wide for the reason ByID is.
	Delete(ctx context.Context, realmID, id string) error
	// List returns one provider's mappers **in the order they were created**,
	// which is not the server's order. Keycloak's listing was measured having
	// none that is reproducible: five mappers created `zzz, mmm, aaa, qqq, bbb`
	// came back `bbb, zzz, qqq, mmm, aaa`, twice in a row on one container and
	// matching neither insertion, name nor anything else on the wire - the ids
	// are minted UUIDs, so nothing about a later run can repeat it. The
	// conformance case masks the array; this order exists so a driver is
	// deterministic where the server is not.
	//
	// It takes no bounds because the listing has none: `first`, `max`, `search`
	// and `briefRepresentation` were each measured returning the whole set, and
	// so was `first=abc`.
	List(ctx context.Context, realmID, alias string) ([]*model.IdentityProviderMapper, error)
}

// ComponentRepo stores a realm's SPI components.
//
// The three query filters - `type`, `parent` and `name` - run in internal/admin
// over what List returns, for the reason the identity providers' do: an unknown
// value on any of them is a measured `[]` rather than a 404, so they are a
// filter over rows this returns and never a lookup that can fail.
type ComponentRepo interface {
	// Create inserts a component and its config, in the order given. The
	// filtering of the config to the provider's declared properties happens in
	// internal/admin, where the catalogue is: this writes what it is handed.
	Create(ctx context.Context, c *model.Component) error
	// Update replaces the row and its whole config with what it is handed.
	// **The merge is not here.** `PUT /components/{id}` merges the config and
	// re-filters it against the body's providerId, and both of those need the
	// catalogue, so internal/admin computes the resulting config and this
	// writes it. Putting the merge behind the SQL boundary would hide a
	// measured contract from the package whose job is to reproduce it -
	// LocalizationRepo's reason, for the same kind of behaviour.
	Update(ctx context.Context, c *model.Component) error
	// Delete removes one by id, and its config with it. ErrNotFound for an id
	// the realm does not have, which is the measured 404: a second delete of
	// the same id answers `Could not find component`, unlike the initial access
	// tokens next door whose repeat delete is a 204.
	Delete(ctx context.Context, realmID, id string) error
	// ByID resolves one. ErrNotFound becomes
	// `404 {"error":"Could not find component"}`, which is a spelling of
	// not-found this API did not previously have. **The realm's own id answers
	// it too**: components are parented on the realm and the realm is not one.
	ByID(ctx context.Context, realmID, id string) (*model.Component, error)
	// List returns every component of one realm in the order bootstrap wrote
	// them. That is **not** Keycloak's order, which was measured having none:
	// two realms on one container returned the same fourteen rows two different
	// ways. The conformance case masks the array rather than asserting either,
	// and this order exists so that a driver is deterministic where the server
	// is not.
	List(ctx context.Context, realmID string) ([]*model.Component, error)
}

// AuthzRepo stores a client's authorization services settings.
//
// **It also owns the client's authorizationServicesEnabled flag**, because that
// flag is the presence of a row here rather than a column on the client. The
// client repositories read it with a subquery and cannot write it; Upsert and
// DeleteByClientID are the only two things that move it. A boolean beside this
// table would be a second truth, and Keycloak's own behaviour says the two
// cannot drift: turning the flag off destroys the settings, measured.
type AuthzRepo interface {
	// Upsert creates the resource server or replaces its three settings.
	//
	// It is one method rather than Create plus Update because the two callers
	// want different halves and neither wants a not-found: turning the flag on
	// writes model.DefaultAuthzResourceServer, and PUT .../authz/resource-server
	// writes the caller's values over a row that is guaranteed to exist because
	// the route's own gate resolved it.
	Upsert(ctx context.Context, rs *model.AuthzResourceServer) error
	// ByClientID returns the resource server, or ErrNotFound when the client
	// has no authorization services. The 404 that ErrNotFound becomes is
	// `{"error":"HTTP 404 Not Found"}` and **not** any of the twenty-one
	// spellings - see guardAuthz.
	ByClientID(ctx context.Context, clientID string) (*model.AuthzResourceServer, error)
	// DeleteByClientID turns the flag off. It is idempotent: a client that
	// never had authorization services is not an error, because
	// PUT /clients/{uuid} sending `"authorizationServicesEnabled":false` twice
	// answers 204 both times.
	DeleteByClientID(ctx context.Context, clientID string) error

	// CreateScope inserts a scope, assigning it the next ordinal within its
	// resource server. A name another scope of the same resource server
	// already holds is ErrConflict, which internal/admin turns into the
	// measured 409 `Duplicate resource error`.
	CreateScope(ctx context.Context, s *model.AuthzScope) error
	// UpdateScope replaces a scope's three fields. It does not move its
	// ordinal: a PUT was measured leaving the settings export's order alone.
	UpdateScope(ctx context.Context, s *model.AuthzScope) error
	// DeleteScope removes one, ErrNotFound when the resource server has no
	// such scope. The 404 that becomes has an **empty body and no
	// Content-Type**, which is not one of the twenty-one spellings of
	// not-found but the absence of one - see writeAuthzScopeNotFound.
	DeleteScope(ctx context.Context, clientID, scopeID string) error
	// ScopeByID and ScopeByName both take the client id, because a scope is
	// addressed within its resource server and not globally: rs1's scope id
	// read through rs2 is a 404, and one name exists in two resource servers
	// at once. Both measured 2026-09-01.
	ScopeByID(ctx context.Context, clientID, scopeID string) (*model.AuthzScope, error)
	ScopeByName(ctx context.Context, clientID, name string) (*model.AuthzScope, error)
	// ListScopes returns every scope of one resource server **in creation
	// order**, which is what GET .../settings serves. The listing beside it is
	// sorted by name, and the sort, the two filters and the paging all run in
	// internal/admin over what this returns - OrganizationRepo's precedent,
	// and here it is what lets one set of rows have two measured orders
	// without two queries.
	ListScopes(ctx context.Context, clientID string) ([]*model.AuthzScope, error)

	// CreateResource inserts a resource, assigning it the next ordinal within
	// its resource server. A name another resource of the same resource server
	// already holds is ErrConflict, which internal/admin turns into the
	// measured 409 `Resource with name [x] already exists.` - **not** the
	// `Duplicate resource error` the scope create answers. Two creates on one
	// resource server, two 409 bodies.
	CreateResource(ctx context.Context, res *model.AuthzResource) error
	// UpdateResource replaces every field and every child row. It does not
	// move the ordinal, for the reason UpdateScope does not: the settings
	// export's order was measured surviving a PUT.
	//
	// **Attributes absent is not the same as Attributes empty**, and the
	// difference is decided in internal/admin rather than here: a PUT omitting
	// `attributes` keeps what is stored and one sending `{}` clears it. The
	// handler passes whichever set should end up stored, so this method always
	// replaces.
	UpdateResource(ctx context.Context, res *model.AuthzResource) error
	// DeleteResource removes one, ErrNotFound when the resource server has no
	// such resource. The 404 that becomes carries a **JSON body** and no
	// Cache-Control, which is the opposite of the scope family's empty-bodied
	// 404 one path segment away.
	DeleteResource(ctx context.Context, clientID, resourceID string) error
	// ResourceByID and ResourceByName both take the client id, because a
	// resource is addressed within its resource server: one server's resource
	// id read through another is a 404 and one name exists in two servers at
	// once. Both measured 2026-09-01, and the id is global all the same - a
	// create naming an id another server holds is a 409.
	ResourceByID(ctx context.Context, clientID, resourceID string) (*model.AuthzResource, error)
	ResourceByName(ctx context.Context, clientID, name string) (*model.AuthzResource, error)
	// ListResources returns every resource of one resource server **in creation
	// order**, which is what GET .../settings serves and also what
	// GET .../scope/{id}/resources serves. The listing beside them sorts by
	// name, and the sort, the six filters, the two modifiers and the two bounds
	// all run in internal/admin over what this returns - ListScopes' precedent,
	// and it is what lets one set of rows have three measured consumers without
	// three queries.
	ListResources(ctx context.Context, clientID string) ([]*model.AuthzResource, error)

	// CreatePolicy inserts a policy - or a permission, which is the same row
	// with one of three types - assigning it the next ordinal within its
	// resource server.
	//
	// **Two constraints, two measured 409 bodies, and internal/admin has to
	// tell them apart.** A name another policy of the same resource server
	// holds is `Policy with name [x] already exists` / `Conflicting policy`; an
	// id **any** resource server holds is `Duplicate resource error`. Both come
	// back as ErrConflict, so the handler checks the name itself before calling
	// this and treats what is left as the id collision - which is also the
	// measured order, the name answering ahead of the id on a body wrong in
	// both ways.
	CreatePolicy(ctx context.Context, p *model.AuthzPolicy) error
	// UpdatePolicy replaces every field and every child row. It does not move
	// the ordinal, for the reason UpdateScope and UpdateResource do not.
	//
	// Its only caller is POST .../import, which was measured **merging** into a
	// policy whose name it already holds rather than replacing it: importing a
	// `regex` body over a `role` policy left the type `role` and merged the
	// config. The merge is decided in internal/admin; this method always
	// replaces what it is handed.
	UpdatePolicy(ctx context.Context, p *model.AuthzPolicy) error
	// PolicyByID and PolicyByName both take the client id, because a policy is
	// addressed within its resource server: one server's policy id read through
	// another is a 404. The id is global all the same - a create naming an id
	// another server holds is a 409, and the **other** server is undamaged,
	// which is the resource family's answer and not F131's.
	PolicyByID(ctx context.Context, clientID, policyID string) (*model.AuthzPolicy, error)
	PolicyByName(ctx context.Context, clientID, name string) (*model.AuthzPolicy, error)
	// ListPolicies returns every policy of one resource server **in creation
	// order**, which is the order GET .../settings serves after moving the
	// `resource` and `scope` rows to the end. The two listings' byte-wise name
	// sort, their ten filters and their two bounds all run in internal/admin
	// over what this returns - ListScopes' and ListResources' precedent, and
	// here it is what lets one set of rows serve two listings, two searches and
	// an export whose orders and partitions all disagree.
	//
	// There is no DeletePolicy: no operation in the description removes one,
	// and the resource server's cascade takes the rows with it.
	ListPolicies(ctx context.Context, clientID string) ([]*model.AuthzPolicy, error)
}

// OrganizationRepo stores a realm's organizations.
//
// It is deliberately small: the listing's search, exact, q, first and max all
// run in internal/admin over what List returns, so the four filters live in one
// place a test can read rather than in two drivers that could disagree about
// what "case-insensitive substring" means.
type OrganizationRepo interface {
	Create(ctx context.Context, o *model.Organization) error
	// Update writes every field back except the alias, which is immutable -
	// a PUT changing it was measured answering 400 "Cannot change the alias",
	// so a driver that could write it would be offering a change nobody has
	// measured.
	Update(ctx context.Context, o *model.Organization) error
	Delete(ctx context.Context, realmID, id string) error
	ByID(ctx context.Context, realmID, id string) (*model.Organization, error)
	// List returns every organization in the realm **ordered by name**, byte
	// order rather than case-insensitively: five organizations created out of
	// order came back `UPPER, aaa-org, mmm-org, with.dot, zzz-org`, with the
	// capital first, which is what says the comparison is not folded.
	List(ctx context.Context, realmID string) ([]*model.Organization, error)
	// ByDomain resolves the organization holding a domain, anywhere in the
	// realm. A domain is unique realm-wide and the measured 400 names the
	// other organization by name - "Domain d is already linked to organization
	// o in realm r" - so the create needs the row rather than a boolean.
	ByDomain(ctx context.Context, realmID, domain string) (*model.Organization, error)

	// AddMember makes a user a member. A user already in the organization is
	// ErrConflict, which internal/admin turns into the measured
	// `409 {"errorMessage":"User is already a member of the organization."}`.
	//
	// It takes a user id and not a membership of any kind: a member **is** a
	// user, addressed by the user's own id on every route in the family.
	AddMember(ctx context.Context, orgID, userID string) error
	// RemoveMember takes a user out. A user who is not a member is ErrNotFound,
	// which becomes the generic `404 {"error":"HTTP 404 Not Found"}` - the same
	// answer a user id that resolves to nothing gets, so the delete does not
	// say which of the two it was. It is **not** idempotent: the second delete
	// is that 404 where a default-group removal is 204.
	RemoveMember(ctx context.Context, orgID, userID string) error
	// IsMember answers the four routes that resolve a member without listing
	// one. It is a predicate rather than a lookup because the user is fetched
	// through UserRepo anyway - the member representation is a user
	// representation - and asking the same row for two things would let the two
	// answers disagree.
	IsMember(ctx context.Context, orgID, userID string) (bool, error)
	// Members returns an organization's members **ordered by username**, which
	// is the measured serving order: three users added `zzz, aaa, mmm` came
	// back `aaa, mmm, zzz`, on a set whose username order and e-mail order
	// deliberately disagree. Paging, `search`, `exact` and `membershipType` all
	// run in internal/admin over this, because `search` here is a
	// case-insensitive **substring** where the user listing's is a prefix and
	// writing that difference twice is writing it twice.
	Members(ctx context.Context, orgID string) ([]*model.User, error)
	// MemberOf returns the organizations one user belongs to, in **no defined
	// order**: four organizations came back `mm, zz, aa, fin` on four
	// consecutive reads of one container - reproducible there, and matching
	// neither insertion order, nor name, nor organization id. The two routes
	// that serve it carry Case.Unordered for exactly that.
	MemberOf(ctx context.Context, realmID, userID string) ([]*model.Organization, error)
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
	// Update writes every mutable column back, providerId included.
	//
	// That the admin API never *moves* providerId is a rule about
	// PUT /required-actions/{alias}, which reads the field off the wire and
	// discards it, and internal/admin is the single place that decides it.
	// This interface held the rule too until a mutation test found that
	// neither copy was pinned: with the store refusing the write, a handler
	// that assigned the body's providerId changed nothing observable, and with
	// the handler not assigning, a store that wrote the column changed nothing
	// either. Two guards, one behaviour, and every single-point mutation
	// invisible. See docs/superpowers/handover/p8-authentication.md.
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
	// ListTopLevel returns the realm's groups with no parent, which is what
	// GET /groups answers - measured top-level only, while the count beside
	// it counts the whole tree.
	//
	// **It excludes every organization group, and so does ListAll.** A realm
	// holding two organization groups was measured answering `[]` here and
	// `{"count":0}` from the count.
	//
	// **ListUserGroups does not**, and that is measured rather than an
	// oversight: `GET /users/{id}/groups` filters them out while
	// `GET /users/{id}/groups/count` beside it **counts** them - one
	// membership, two routes, two answers - so the filter has to sit above the
	// store, where only one of the two applies it.
	ListTopLevel(ctx context.Context, realmID string) ([]*model.Group, error)
	ListChildren(ctx context.Context, realmID, parentID string) ([]*model.Group, error)
	// Move reparents one group. It is separate from Update because Update
	// deliberately cannot write parent_id: the realm family has no operation
	// that reparents a group, and the organization family has two - the body's
	// `id` on both creates is a move rather than a create, measured 204 with an
	// empty body where the create beside it answers 201 with the group.
	Move(ctx context.Context, realmID, id, parentID string) error
	// ListOrganizationAll returns every group of one organization at any
	// depth, ordered by name, **without** its hidden root. The listing, the
	// search and the group-by-path walk all read it.
	ListOrganizationAll(ctx context.Context, realmID, orgID string) ([]*model.Group, error)
	// OrganizationRoot returns the group Keycloak creates with an
	// organization. Its `name` and its `path` are the organization's own id,
	// it is the parent of every group at the top of the organization, and the
	// listing never shows it - `GET /organizations/{org}/groups` answers its
	// children.
	OrganizationRoot(ctx context.Context, realmID, orgID string) (*model.Group, error)
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

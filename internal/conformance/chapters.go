package conformance

// Chapter is one slice of the parity surface, with the source of its
// denominator named.
//
// A percentage is only as good as its denominator. If the denominator is
// "cases somebody bothered to write down", it measures diligence rather than
// coverage: it grows when someone remembers a gap and shrinks when they
// forget one, and it reads best when the catalogue is worst. So chapters say
// where their number comes from, and the ones nobody has counted say that too
// rather than being quietly left out of the total - which would inflate the
// percentage by hiding exactly the parts nobody has looked at.
//
// See docs/superpowers/specs/2026-08-21-gloak-parity-roadmap.md section 3.
type Chapter struct {
	// Name is the report's row label. For a chapter the catalogue covers it
	// matches chapterOf(case.ID).
	Name string

	// OpenAPITag names the tag in the vendored description whose operations
	// are this chapter's denominator. Empty means the denominator is the
	// number of catalogue cases instead.
	OpenAPITag string

	// Enumerated is false when nobody has counted this chapter's surface.
	// The report prints "?" for its denominator and keeps it out of the
	// total, saying how many chapters it left out.
	Enumerated bool

	// Reason says why the surface is not counted. Required when Enumerated
	// is false, forbidden when it is true.
	Reason string
}

// Chapters is the whole parity surface: the hand-written protocol chapters
// the catalogue covers, every tag of the vendored Admin API description, and
// the chapters whose surface has no machine-readable source and has not been
// counted by hand either.
var Chapters = []Chapter{
	// Protocol chapters. Their denominator is the catalogue's own case count,
	// which is a hand-kept number and is reported as such.
	{Name: "http/fallback", Enumerated: true},
	{Name: "oidc/authorization", Enumerated: true},
	{Name: "oidc/certs", Enumerated: true},
	{Name: "oidc/ciba", Enumerated: true},
	{Name: "oidc/device", Enumerated: true},
	{Name: "oidc/discovery", Enumerated: true},
	{Name: "oidc/introspection", Enumerated: true},
	{Name: "oidc/logout", Enumerated: true},
	{Name: "oidc/registration", Enumerated: true},
	{Name: "oidc/revocation", Enumerated: true},
	{Name: "oidc/token", Enumerated: true},
	{Name: "oidc/userinfo", Enumerated: true},
	{Name: "realm/info", Enumerated: true},

	// Admin REST API. One chapter per tag, so every operation in the
	// description is counted exactly once. An operation is counted under the
	// sub-project that builds the resource, which is not always the one that
	// cares about it: realm export and import and the events configuration
	// are Realms Admin operations, though the behaviour behind them belongs
	// to the operational-parity sub-project.
	{Name: "admin/attack-detection", OpenAPITag: "Attack Detection", Enumerated: true},
	{Name: "admin/authentication-management", OpenAPITag: "Authentication Management", Enumerated: true},
	{Name: "admin/authz-resource-server", OpenAPITag: untaggedTag, Enumerated: true},
	{Name: "admin/client-attribute-certificate", OpenAPITag: "Client Attribute Certificate", Enumerated: true},
	{Name: "admin/client-initial-access", OpenAPITag: "Client Initial Access", Enumerated: true},
	{Name: "admin/client-registration-policy", OpenAPITag: "Client Registration Policy", Enumerated: true},
	{Name: "admin/client-role-mappings", OpenAPITag: "Client Role Mappings", Enumerated: true},
	{Name: "admin/client-scopes", OpenAPITag: "Client Scopes", Enumerated: true},
	{Name: "admin/clients", OpenAPITag: "Clients", Enumerated: true},
	{Name: "admin/component", OpenAPITag: "Component", Enumerated: true},
	{Name: "admin/groups", OpenAPITag: "Groups", Enumerated: true},
	{Name: "admin/identity-providers", OpenAPITag: "Identity Providers", Enumerated: true},
	{Name: "admin/key", OpenAPITag: "Key", Enumerated: true},
	{Name: "admin/organizations", OpenAPITag: "Organizations", Enumerated: true},
	{Name: "admin/protocol-mappers", OpenAPITag: "Protocol Mappers", Enumerated: true},
	{Name: "admin/realms-admin", OpenAPITag: "Realms Admin", Enumerated: true},
	{Name: "admin/role-mapper", OpenAPITag: "Role Mapper", Enumerated: true},
	{Name: "admin/roles", OpenAPITag: "Roles", Enumerated: true},
	{Name: "admin/roles-by-id", OpenAPITag: "Roles (by ID)", Enumerated: true},
	{Name: "admin/scope-mappings", OpenAPITag: "Scope Mappings", Enumerated: true},
	{Name: "admin/users", OpenAPITag: "Users", Enumerated: true},
	{Name: "admin/workflows", OpenAPITag: "Workflows", Enumerated: true},

	// Surface with no machine-readable description, not counted by hand
	// either. Listed so the report can say how much it is not measuring.
	{
		Name:   "saml",
		Reason: "no machine-readable description; the SAML endpoints have not been enumerated by hand",
	},
	{
		Name:   "account",
		Reason: "the account REST API is not described by the Admin API document and has not been enumerated",
	},
	{
		Name:   "themes",
		Reason: "themes and i18n are served as resources, not as an API; no operation list exists",
	},
	{
		Name:   "management",
		Reason: "the management port's health and metrics endpoints are not in the Admin API document",
	},
}

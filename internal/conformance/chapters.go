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
	// The protocol dispatcher, not one endpoint. Its four cases are what
	// /realms/{realm}/protocol/{name} answers when {name} is not a protocol
	// Keycloak registered, or is one and the path under it serves nothing.
	// It is a chapter of its own rather than rows in http/fallback because
	// the answer is decided by Keycloak's protocol map and not by whether a
	// route matched - which is exactly what the two fallback bodies mean.
	{Name: "oidc/protocol", Enumerated: true},
	{Name: "oidc/registration", Enumerated: true},
	{Name: "oidc/revocation", Enumerated: true},
	{Name: "oidc/token", Enumerated: true},
	{Name: "oidc/userinfo", Enumerated: true},
	{Name: "realm/info", Enumerated: true},

	// SAML 2.0, enumerated by hand on 2026-09-07 and no longer a "?" row.
	//
	// There is no machine-readable description for this surface - the vendored
	// Admin API document does not describe it - so the denominator is the
	// catalogue's own case count, the same weak kind the OIDC chapters use.
	// What it rests on is a **sweep**: five route shapes under
	// /realms/{realm}/protocol/saml crossed with seven verbs, plus the request
	// families the message-reading paths distinguish and the realm and protocol
	// variations, is 72 request/response pairs measured against a live 26.7.1.
	// Twenty-two of the 35 verb cells are the generic fallback family -
	// seventeen 405s and five `HTTP 404 Not Found` - which http/fallback already
	// counts once for the whole API and which are **not** counted again here;
	// counting them per path would report the same two behaviours twenty-two
	// times. The rest collapse to the cases in catalog_saml.go. See
	// docs/superpowers/handover/p11-saml-descriptor.md for the table.
	//
	// One chapter per route shape, which is how the OIDC side is split, and it
	// is worth being explicit that a chapter is not an endpoint: saml/endpoint
	// is one path with six distinct answers over two verbs.
	{Name: "saml/descriptor", Enumerated: true},
	{Name: "saml/endpoint", Enumerated: true},
	{Name: "saml/idp-initiated", Enumerated: true},
	{Name: "saml/artifact-resolution", Enumerated: true},

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

	// The account REST API, enumerated by hand on 2026-09-07 and no longer a
	// "?" row.
	//
	// There is no machine-readable description for this surface either, so the
	// denominator is the catalogue's own case count. What it rests on is a
	// sweep, and the sweep needed a **different discriminator** from the SAML
	// one: every path under /realms/{realm}/account answers 200 with the
	// account console's markup to a request that did not ask for JSON,
	// including paths no route serves, so the two 404 bodies never appear and a
	// sweep run that way would have found an infinite surface. The request's
	// `Accept` decides which of two APIs the path is, and the REST resource is
	// reached exactly when the accept list holds `application/json` with no
	// parameters - `application/json;q=1` is the console.
	//
	// With that header the sweep gives sixteen route shapes and 119 verb cells.
	// Almost all of the cells are the generic fallback family, which
	// http/fallback already counts once for the whole API and which are **not**
	// counted again here; two that look like it are counted, because they are
	// not it - PATCH on /resources is a 403 rather than a 405, and OPTIONS is a
	// 200 with no Allow header at all. See
	// docs/superpowers/handover/account-api.md for the table.
	//
	// One chapter per route family, which is how the OIDC and SAML sides are
	// split. account/gate is a chapter because the gate is two stages with two
	// statuses and per-route role sets, which is behaviour rather than plumbing.
	{Name: "account/gate", Enumerated: true},
	{Name: "account/groups", Enumerated: true},
	{Name: "account/linked-accounts", Enumerated: true},
	{Name: "account/supported-locales", Enumerated: true},
	{Name: "account/profile", Enumerated: true},
	{Name: "account/credentials", Enumerated: true},
	{Name: "account/sessions", Enumerated: true},
	{Name: "account/applications", Enumerated: true},
	{Name: "account/resources", Enumerated: true},
	{Name: "account/console", Enumerated: true},
	{Name: "account/dispatch", Enumerated: true},

	// Themes, enumerated by hand on 2026-09-15 and no longer a "?" row. It was
	// the last one, so the report no longer says "N chapters not enumerated" at
	// all.
	//
	// Its declared reason was *"themes and i18n are served as resources, not as
	// an API; no operation list exists"*, and two of those three clauses do not
	// survive being measured. **i18n is served as an API and is already
	// enumerated**: nineteen Implemented cases under
	// admin/realms-admin/localization-*, two Recorded ones under
	// account/supported-locales, and the part of i18n that genuinely is a theme
	// resource - every theme's `messages/messages_*.properties` - is 404 on the
	// resource route, which themes/resource/messages-not-served records. And
	// **"no operation list exists" is true of SAML, of the account API and of
	// the management port too**, all three of which were counted by hand; it
	// describes every chapter in this file whose denominator is a case count
	// rather than giving a reason not to have one. Only the middle clause was
	// load-bearing, and what it argues for is a different **unit**, not the
	// absence of one.
	//
	// The unit is **an answer the route gives that a request can distinguish
	// without knowing which file it named**. Keycloak's themes hold about twelve
	// hundred servable files; they say one thing between them, and counting them
	// per file would report one behaviour twelve hundred times - which is the
	// SAML cut's decision about the fallback family and the management cut's
	// about the verb dimension, applied to the dimension this surface has. The
	// file dimension collapses because it was **measured** collapsing:
	// `css/styles.css` is one md5 across two start-dev containers with different
	// databases and a third in production mode, and the consoles' content-hashed
	// asset names are identical across all three. The only part of a theme URL
	// that moves is the version segment.
	//
	// What does not collapse is eighteen behaviours over one route,
	// `/resources/{version}/{themeType}/{themeName}/{path}`: a stale version is
	// a 307 to the current one but only after the file resolves and not on the
	// fallback-theme path; the version segment is validated against
	// `[0-9a-z]{5}` before anything else is looked at; an unknown theme **name**
	// serves the default theme's bytes where an unknown **type** is a 404; the
	// type ignores case and the version does not; a theme's root directory is a
	// 200 with no bytes; only `resources/` inside a theme is reachable, so the
	// templates, `theme.properties` and the message bundles are all refused; the
	// route has no `ETag`, no `Last-Modified` and no negotiation of any kind;
	// and it carries **four** of the five security headers, missing
	// `X-Frame-Options`.
	//
	// **The boundary with P13 is that this chapter is the other end of the URLs
	// P13's pages mint.** Thirty-eight goldens hold
	// `/resources/{{theme_resource}}/` inside a body and every one is counted
	// under the endpoint that rendered it, which is what
	// TestThemeResourceAppearsOnlyInTheThemePages already enumerates. A page
	// rendered from a theme is counted where it is served - account/console is
	// the precedent - and the machinery a theme is served *by* is counted here.
	// Two theme-rendered pages are counted in neither place and are named rather
	// than quietly absorbed: `/` and `/admin/{realm}/console/`. See F252.
	//
	// The discriminator is a **fourth**, and none of the three published here is
	// general. p11's pair of 404 bodies needs two distinct ones; this route has
	// one, and it is a body of zero bytes. account-api's "at least one verb
	// answers outside the fallback family" cannot separate a file that exists
	// from one that does not, since both are GET-only. The management port's "a
	// route answers its own 200 on all seven verbs" is false here, where GET and
	// HEAD answer and the other five are 405. What enumerates this one was
	// validated in both directions on one container before it was used: **a
	// request naming a resource that resolves answers 200 with its bytes and a
	// media type; one that does not answers 404 with no body and no
	// `Content-Type`.** The transferable part is the validation, not the test.
	//
	// One chapter per family, which is how the OIDC, SAML, account and
	// management sides are split. themes/version is a chapter of its own because
	// the version segment is the only part of a theme URL that belongs to the
	// installation rather than to the theme tree, and it is the one thing on
	// this surface a reimplementation has to mint rather than copy. See
	// docs/superpowers/handover/themes-chapter.md for the grid and the
	// alternative rejected.
	{Name: "themes/resource", Enumerated: true},
	{Name: "themes/version", Enumerated: true},

	// The management interface, enumerated by hand on 2026-09-15 and no longer
	// a "?" row.
	//
	// There is no machine-readable description for this surface either, so the
	// denominator is the catalogue's own case count. What it rests on is a
	// sweep, and the sweep needed a **third discriminator**: neither of the two
	// this repository already has works here.
	//
	// p11 swept candidate paths against Keycloak's pair of 404s - an unmatched
	// path answering `Unable to find matching target resource method` with none
	// of the five security headers, a known path answering `HTTP 404 Not Found`
	// with all five. The management port has neither body. account-api.md fell
	// back to "a route exists when at least one verb answers outside the
	// generic fallback family, with OPTIONS excluded, because OPTIONS answers
	// 200 on every path". **Here every verb answers 200 on every path that is a
	// route**, so that test would have accepted nothing it was not already sure
	// of.
	//
	// What enumerates this one is simpler than both, and it was validated in
	// both directions on one container before it was used: **a route answers
	// its own 200 on all seven verbs, and a path that is not a route answers
	// `404 <html><body><h1>Resource not found</h1></body></html>`,
	// `text/html; charset=utf-8`, 53 bytes, on all seven.** Eleven paths by
	// seven verbs is 77 cells with no third answer in them.
	//
	// That gives ten route shapes and 16 catalogued behaviours. The verb
	// dimension collapses entirely - 70 of the 77 cells are the one fact that
	// the verb decides nothing here - so it is counted **once**, which is the
	// SAML cut's decision about the fallback family and the one part of its
	// method that transfers. The seven control cells are not counted at all.
	//
	// The surface enumerated is the **enabled** one, not the default
	// container's. A default `start-dev` has no listener on 9000 at all, so
	// "the default surface" is not a surface: it is the absence of one, and a
	// chapter recording it would be recording that a feature is off as though
	// that were a contract. F169 is the precedent - CIBA's 503 was an artefact
	// of a startup option and read as a missing feature for weeks. See
	// docs/superpowers/handover/management-port.md for the grid and the
	// rejected alternative.
	//
	// One chapter per route family, which is how the OIDC, SAML and account
	// sides are split, and the old single `management` row is gone the way the
	// old `saml` row went. management/fallback is a chapter of its own and is
	// **not** rows in http/fallback: that chapter counts the two bodies
	// Keycloak's application serves, and this is a third body from Quarkus's
	// management router, which the application never sees.
	{Name: "management/index", Enumerated: true},
	{Name: "management/health", Enumerated: true},
	{Name: "management/metrics", Enumerated: true},
	{Name: "management/fallback", Enumerated: true},
}

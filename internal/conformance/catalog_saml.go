package conformance

import "net/http"

// samlCases is the SAML 2.0 surface, enumerated by hand against a live
// Keycloak 26.7.1 on 2026-09-07 because nothing describes it.
//
// # What the sweep found
//
// Five route shapes exist under `/realms/{realm}/protocol/saml`, and the
// discriminator is Keycloak's own: an unmatched path answers
// `{"error":"Unable to find matching target resource method"}` with **none** of
// the five security headers, and a path the router knows answers
// `{"error":"HTTP 404 Not Found"}` with all five. Everything below is on the
// second side of that line.
//
//	/realms/{realm}/protocol/saml                  the SSO and SLO bindings
//	/realms/{realm}/protocol/saml/descriptor       the IdP metadata
//	/realms/{realm}/protocol/saml/resolve          artifact resolution
//	/realms/{realm}/protocol/saml/clients/{name}   IdP-initiated SSO
//	anything else under /protocol/saml/            the generic 404
//
// Seven verbs on each is a 35-cell sweep, and **22 of those 35 are the generic
// fallback family** - seventeen 405s (PUT, DELETE and PATCH on all five, plus
// HEAD on /resolve and on /clients) and five `HTTP 404 Not Found` - which
// `http/fallback` already counts once for the whole API and which are not
// counted again here; counting them per path would report two behaviours
// twenty-two times. Thirteen cells are left. Adding the request families the
// message-reading paths distinguish, and the realm and protocol variations,
// makes **72 request/response pairs measured in all**; the table is in
// docs/superpowers/handover/p11-saml-descriptor.md. They collapse to the
// cases below.
//
// # Four things that are not what a reader would guess
//
//   - **`GET /protocol/saml` and `GET /protocol/openid-connect/auth`, both with
//     no parameters, answer the byte-identical 3572-byte 400 page and
//     complementary header sets.** The SAML one sends
//     `Cache-Control: no-store, must-revalidate, max-age=0` and none of the five
//     security headers and no `Content-Security-Policy`; the OIDC one sends all
//     six and no `Cache-Control`. Measured at socket level on one container,
//     side by side. Two protocol endpoints, one page, opposite answers.
//   - **The `Issuer` decides which of three sentences a request gets**, and the
//     ladder's rungs are 3572, 3579 and 3604 bytes: no client resolves is
//     `Invalid Request`, an `openid-connect` client is `Wrong client protocol.`,
//     and a `saml` client is `Invalid requester`. A case set breaking one thing
//     at a time never reaches the second or third rung.
//   - **The segment in `/protocol/saml/clients/{name}` is not a clientId.** It
//     is the client's `saml_idp_initiated_sso_url_name` attribute. One client
//     answers `Client not found.` for its own clientId and `Invalid redirect
//     uri` for the attribute's value, measured on the same container.
//   - **`application/xml` and `text/xml` disagree about `X-Frame-Options`.** The
//     descriptor's `application/xml;charset=UTF-8` carries all five security
//     headers; the artifact resolution response's `text/xml` carries four. Two
//     XML media types one path segment apart.
//
// # What is served and what is not
//
// The descriptor alone, and it is the anchor rather than the first slice of a
// bigger build: it is the one SAML response that is a pure function of the realm
// and needs neither an assertion builder nor a browser.
//
// The rest is Recorded, and the reason is one measurement rather than an
// estimate of effort. **The success path is reachable**, and the cut found it
// while looking for something else: with `saml.client.signature` turned off - it
// is `"true"` on every client `POST /clients` creates with `protocol: saml` -
// the same AuthnRequest that answers `Invalid requester` answers **200 with the
// login page**, 6869 bytes. So `Invalid requester` means "the requester was not
// authenticated", the rejection ladder is five deep (client, protocol,
// signature, Destination, assertion consumer URL), and a handler that served
// these rejections without walking it would be right on every request in this
// catalogue and wrong on the only request a SAML client ever sends. That is the
// shape AGENTS.md calls "a set of assertions an incorrect implementation
// satisfies entirely".
var samlCases = []Case{
	// ---------------------------------------------------------------- descriptor

	{
		ID: "saml/descriptor/master",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "IDP metadata descriptor: GET /realms/{realm}/protocol/saml/descriptor",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		// No Operation, and that is a rule rather than an omission: the SAML
		// chapters count **cases**, because the vendored description says
		// nothing about this surface, and naming an operation would suggest an
		// external denominator that does not exist.
		// TestProtocolCasesNameNoOperation refuses one.
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/saml/descriptor",
		},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		// The realm's RSA key is minted with the database, so the two values
		// derived from it vary and nothing else in this document does. Measured
		// 2026-09-07: five requests to one container gave byte-identical bodies,
		// and two containers from one image differed in exactly these two
		// places. It is oidc/certs/master's declaration - keys/*/kid and
		// keys/*/x5c - in the dialect the descriptor is written in.
		//
		// The mask is over the element text and not over the body, so the golden
		// still asserts the entityID, all four namespace declarations (including
		// the default one nothing uses and the `saml` one no element is in),
		// WantAuthnRequestsSigned, protocolSupportEnumeration, use="signing",
		// ArtifactResolutionService's index="0" and its lone Location under
		// /resolve, the four SingleLogoutService bindings in their order, the
		// four NameIDFormats in theirs, the four SingleSignOnService bindings in
		// a **different** order from the logout ones, and Keycloak's habit of
		// spelling every empty element <md:X></md:X> rather than <md:X/>.
		VolatileXMLText: []string{"ds:KeyName", "ds:X509Certificate"},
	},
	{
		ID: "saml/descriptor/second-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "IDP metadata descriptor: GET /realms/{realm}/protocol/saml/descriptor",
			Retrieved: "2026-09-07",
		},
		Status:      Implemented,
		SecondRealm: true,
		Fixture:     "second-realm",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/gloak-probe-second/protocol/saml/descriptor",
		},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		// Nine values in this document are derived from the realm name - the
		// entityID and eight service Locations - and a handler answering with
		// the literal `master` would compare equal to one deriving them on the
		// master case alone. That is F142's mutation and this is the case that
		// sees it. ReplaceIssuer rewrites the base URL and deliberately not the
		// realm segment, which is what leaves the name asserted.
		VolatileXMLText: []string{"ds:KeyName", "ds:X509Certificate"},
	},
	{
		ID: "saml/descriptor/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "IDP metadata descriptor: an unknown realm",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/nosuchrealm/protocol/saml/descriptor",
		},
		// The protocol side's spelling, `Realm does not exist`, with no full
		// stop - not the Admin API's `Realm not found.`. It carries no
		// Cache-Control where the 200 beside it carries no-cache, which is the
		// discovery endpoint's split reproduced here.
		//
		// It names no Operation on purpose: a rejection proves the route exists
		// and refuses correctly, not that the operation does its job, and the
		// case above already claims the operation.
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// `Protocol not found` for any protocol Keycloak has not registered.
		// **Not a SAML behaviour** - /protocol/nosuchproto/certs and a bare
		// /protocol/nosuchproto answer the same sentence - which is why the
		// dispatcher that serves it lives in internal/oidc's router and why
		// oidc/protocol holds the rest of its cells. This one stays here
		// because this is the sweep that found it, and because the descriptor
		// path is the cell that proves the dispatch beats a route Gloak
		// really serves one segment along.
		//
		// Implemented since 2026-09-07 by handler.protocolDispatch.
		ID: "saml/descriptor/unknown-protocol",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "IDP metadata descriptor: an unregistered login protocol",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/nosuchproto/descriptor",
		},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/descriptor/options",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "IDP metadata descriptor: OPTIONS",
			Retrieved: "2026-09-07",
		},
		Status:  Recorded,
		Fixture: "bootstrap",
		Reason: "OPTIONS answers 200 with Allow: HEAD, POST, GET, OPTIONS and four of the " +
			"five security headers - X-Frame-Options is absent, which is that rule's " +
			"OPTIONS cell. Gloak answers OPTIONS with the fallback 404 on every route it " +
			"has, so this is F31's standing divergence reached on a new path rather than " +
			"a gap in this cut. What is new is that **all four SAML paths send the " +
			"identical Allow**, so it describes the parent resource and not the path: " +
			"/descriptor advertises POST and answers it 404, and /resolve advertises GET " +
			"and answers it 404.",
		Request: Request{
			Method: http.MethodOptions,
			Path:   "/realms/master/protocol/saml/descriptor",
		},
		AssertHeaders: []string{
			"Allow",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Robots-Tag",
		},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},

	// ------------------------------------------------------------------ endpoint

	{
		ID: "saml/endpoint/no-parameters",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: GET with no SAMLRequest",
			Retrieved: "2026-09-07",
		},
		// Implemented since 2026-09-11 by handler.samlEndpoint, the ladder's
		// floor: a request carrying no SAMLRequest at all.
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/saml",
		},
		// **The finding of this cut.** This page and GET
		// /protocol/openid-connect/auth with no client_id are byte-identical,
		// 3572 bytes each, both instructed `Invalid Request` - and their header
		// sets are complementary. Measured at socket level on one container on
		// 2026-09-07, because AGENTS.md's rule about writing down an absence
		// says to dump the bytes that actually left.
		//
		// AssertAbsentHeaders is what carries it. AssertHeaders can only check a
		// header that is named, so without this the day Gloak started sending
		// the five here "for consistency" would look like a pass.
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/post-no-parameters",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: POST with an empty form",
			Retrieved: "2026-09-07",
		},
		// A POST carrying an empty form answers the same 3572-byte **body** the
		// GET does, which is what says the two verbs are one handler here. It
		// is worth a case because /auth is the opposite: POST /auth reads the
		// body and ignores the query, so its two verbs answer differently to
		// the same parameters, and a reader generalising from that endpoint
		// would expect a difference.
		//
		// **The two verbs do differ, and in a header rather than in the body.**
		// This one sends `Cache-Control: no-cache` where the GET beside it sends
		// `no-store, must-revalidate, max-age=0`, on one path with one body -
		// re-measured 2026-09-11 on every rung of the ladder, and true on all of
		// them including the 500 a LogoutRequest gets. So the verb decides the
		// Cache-Control and nothing else, which is the sharpest form of
		// AGENTS.md's "Cache-Control is pinned per endpoint": here it is pinned
		// per endpoint **and verb**.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/saml",
			Form:   map[string]string{"": ""},
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/redirect-binding-unregistered-issuer",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: HTTP-Redirect binding, an Issuer no client carries",
			Retrieved: "2026-09-07",
		},
		// The floor of the Issuer ladder, and the row without which the cases
		// below prove nothing. A well-formed AuthnRequest whose Issuer names no
		// client answers the **same 3572 bytes** an empty request does, so the
		// endpoint's answers split on which client resolved rather than on
		// whether a message was read.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: "SAMLRequest=" + probeAuthnRequestUnregistered,
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/redirect-binding-wrong-protocol",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: an Issuer naming an openid-connect client",
			Retrieved: "2026-09-07",
		},
		// An Issuer naming a registered **openid-connect** client is
		// `Wrong client protocol.`, 3579 bytes, where an unregistered one is
		// 3572. It uses the bootstrapped `account` client, so the input needs no
		// fixture and cannot drift.
		//
		// Note the direction: the scope evaluator serves **both** protocols on
		// one route and refusing the mismatch there is wrong on four
		// operations, while here the mismatch is the answer.
		//
		// **The page names no client**, although one resolved - the restart URL
		// in its head carries no client_id where `Invalid requester`'s does.
		// That is the rule internal/oidc/themepage.go records from the /auth
		// side, and it is the reason this case's golden and
		// signature-over-another-message's disagree about more than a sentence.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: "SAMLRequest=" + probeAuthnRequestOIDCClient,
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/redirect-binding-saml-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: HTTP-Redirect binding, a registered SAML client",
			Retrieved: "2026-09-07",
		},
		// `Invalid requester` is the **signature** refusal and not "the client is
		// unknown": the client resolved. Every client POST /clients creates with
		// protocol saml carries `saml.client.signature: "true"`, so the default
		// SAML client requires one and this unsigned request has none.
		//
		// **This case alone is satisfied by a verifier that refuses
		// everything**, which is why it is one of three rather than one. Its
		// pair is saml/endpoint/redirect-binding-signature-accepted, where a
		// genuinely signed request from a client whose key the fixture pins
		// moves one rung up; and saml/endpoint/redirect-binding-signature-over-
		// another-message, where a real signature attached to a different
		// message comes back here. A verifier that accepts everything fails the
		// third, one that refuses everything fails the second, and this one is
		// what says the flag is read at all.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "saml-service-provider",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: "SAMLRequest=" + probeAuthnRequestSAMLClient,
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/post-binding-saml-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: HTTP-POST binding, a registered SAML client",
			Retrieved: "2026-09-07",
		},
		// The POST binding carries the AuthnRequest base64'd and **not**
		// deflated, which is the one thing about it a reader would get wrong
		// from the GET case: the same message deflated is unreadable here and
		// the same message raw is unreadable there, and both unreadable
		// spellings fall to `Invalid Request`. The two bindings reach the
		// identical **body** once the message is decoded; they differ in the
		// Cache-Control, as post-no-parameters above records.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "saml-service-provider",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/saml",
			Form:   map[string]string{"SAMLRequest": probeAuthnRequestPOSTBinding},
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		// The realm is resolved before the request is read: an unknown realm
		// answers 404 {"error":"Realm does not exist"} **with** the five
		// security headers, where the same path on master answers a page with
		// none of them. Two rejections on one path produced at different
		// depths of one request, and the deeper one is the one that loses the
		// headers.
		//
		// Implemented since 2026-09-07 by handler.protocolDispatch, which
		// resolves the realm first for exactly this reason. It is the case
		// that fails if that order is ever swapped.
		ID: "saml/endpoint/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: an unknown realm",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/nosuchrealm/protocol/saml",
		},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		// The discriminator this whole enumeration rests on, kept as a case so
		// it is checkable rather than asserted in a comment. A path under
		// /protocol/saml/ that no route serves answers
		// {"error":"HTTP 404 Not Found"} with **all five** security headers,
		// where a path outside the realm tree answers
		// {"error":"Unable to find matching target resource method"} with none
		// - so the router reached its resource and found nothing to run. It is
		// the shape AGENTS.md records under /organizations, met on a second
		// family.
		//
		// Implemented since 2026-09-07 by handler.protocolDispatch. It is the
		// case that fails if the dispatcher ever stops distinguishing a
		// registered protocol from an unregistered one, because this path
		// would then answer `Protocol not found`.
		ID: "saml/endpoint/unknown-subpath",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "A path under /protocol/saml that no route serves",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/saml/nosuchsubpath",
		},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/login-page",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: an AuthnRequest that is honoured",
			Retrieved: "2026-09-07",
		},
		Status:  Pending,
		Fixture: "saml-service-provider-unsigned",
		Reason: "**Measured, sendable since 2026-09-11, and still unrecordable.** An " +
			"AuthnRequest from a client with saml.client.signature off, naming an " +
			"assertion consumer URL its redirectUris cover, answers 200 with the login " +
			"page - and the request below is that request, which it could not have been " +
			"before this cut. " +
			"**The blocker this case used to carry first is gone and was wrong.** It " +
			"said the Destination is validated and has to be the base URL the server is " +
			"reachable on, so no literal could work on the recorder's mapped port. " +
			"Re-measured one cell at a time: an AuthnRequest with **no Destination " +
			"attribute at all** reaches the login page, and so does one with " +
			"Destination=\"\". Only a *present and non-empty* Destination is compared, " +
			"and only a request carrying a Signature parameter is required to have one. " +
			"So the port comes out of the message and the literal works everywhere - " +
			"which is why F175's Fixture.SAMLRequests was not built. " +
			"What remains is the second blocker, unchanged: the page carries a " +
			"per-request tab_id and a session_code in its form action, so it cannot be " +
			"Recorded - F113 - and it is the tenth page of the family AGENTS.md already " +
			"records nine of. " +
			"Gloak answers this request with the protocol dispatcher's `HTTP 404 Not " +
			"Found`, deliberately: handler.samlEndpoint walks every rung of the ladder " +
			"and, having no assertion builder behind it, declines to invent an answer " +
			"for the one request that would succeed rather than refusing it with a " +
			"sentence that would be false.",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: "SAMLRequest=" + probeAuthnRequestLoginPage,
		},
	},
	{
		ID: "saml/endpoint/disabled-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: an Issuer naming a disabled client",
			Retrieved: "2026-09-11",
		},
		// **The rung the first cut's five-deep ladder had no room for, and it
		// runs before the protocol check.** The Issuer here names a disabled
		// **openid-connect** client, and the answer is `Login requester not
		// enabled` (3584 bytes) rather than `Wrong client protocol.` - so a
		// handler ordered client, protocol, signature answers the wrong
		// sentence to every disabled client that is not a SAML one, and the two
		// cases a reader writes first (a disabled SAML client, an enabled OIDC
		// one) cannot see it.
		//
		// The sentence is **new to this repository** and has no full stop,
		// where `Client disabled.` - the answer the IdP-initiated route one
		// path segment down gives the same client in the same state - has one.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "saml-refused-clients",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: "SAMLRequest=" + probeAuthnRequestDisabledClient,
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/bearer-only-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: an Issuer naming a bearer-only client",
			Retrieved: "2026-09-11",
		},
		// The second rung the first cut's ladder had no room for, and it runs
		// before the protocol check too: this Issuer names a bearer-only
		// **openid-connect** client and the answer is the bearer-only sentence
		// (3623 bytes), not `Wrong client protocol.` Measured again on a
		// bearer-only SAML client that also requires a signature, which answers
		// this rather than `Invalid requester` - so it is ahead of that check
		// as well.
		//
		// The sentence itself is not new: internal/oidc/themepage.go's
		// pageBearerOnly is /auth's, measured a fortnight earlier. What is new
		// is that this endpoint shares it, which is worth a case because the
		// two endpoints disagree about **every** other sentence on this ladder.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "saml-refused-clients",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: "SAMLRequest=" + probeAuthnRequestBearerOnlyClient,
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/destination-mismatch",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: an AuthnRequest whose Destination is not this server",
			Retrieved: "2026-09-11",
		},
		// The Destination rung. The message names port 8080 and the server is
		// on neither 8080 nor whatever testcontainers mapped, so this request
		// is refused on **both** sides for the same reason and carries no port
		// dependency of its own.
		//
		// Two things are pinned here that nothing else pins. The comparison is
		// **exact**: a trailing slash, `https` for `http`, `127.0.0.1` for
		// `localhost`, the port left off, a query appended, another realm and
		// another path were each measured refused on 2026-09-11. And the page
		// **names the client**, where the `Invalid Request` at the Issuer rung
		// does not - one sentence, two bodies, and the golden is what tells
		// them apart.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "saml-service-provider-unsigned",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: "SAMLRequest=" + probeAuthnRequestWrongDestination,
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/no-assertion-consumer-url",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: an AuthnRequest naming no assertion consumer URL",
			Retrieved: "2026-09-11",
		},
		// The top rung this cut serves: `Invalid redirect uri`. The client has
		// a registered redirectUris pattern and no
		// saml_assertion_consumer_url_post attribute, and the message names no
		// AssertionConsumerServiceURL, so nothing resolves.
		//
		// **It also pins that a Destination is optional**, which is the
		// measurement that made this whole chapter reachable from a catalogue.
		// This message carries none at all; if the Destination were required
		// the answer would be `Invalid Request` two bytes shorter and one rung
		// down, and the golden would say so.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "saml-service-provider-unsigned",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: "SAMLRequest=" + probeAuthnRequestNoAssertionConsumer,
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/unregistered-assertion-consumer-url",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: an assertion consumer URL the client did not register",
			Retrieved: "2026-09-11",
		},
		// **The distinguishing input of the assertion-consumer rung**, and its
		// golden is byte-identical to the case above on purpose. The message
		// names an AssertionConsumerServiceURL that the client's redirectUris
		// do not cover, and without this row a handler that ignored the
		// message's ACS entirely would satisfy the case above and every other
		// case in this chapter.
		//
		// The rule it pins is the one a reader would get wrong. A named ACS is
		// checked against the client's **redirectUris**, by the same predicate
		// an OIDC redirect_uri goes through - all seven of matchRedirectURI's
		// sharp cells were re-measured here and agree - while an **absent** one
		// falls back to the client's saml_assertion_consumer_url_post attribute
		// and is not checked against redirectUris at all. So a client whose
		// only ACS is that attribute, sent a message naming that same URL, is
		// refused. Measured directly on 2026-09-11.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "saml-service-provider-unsigned",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: "SAMLRequest=" + probeAuthnRequestUnregisteredAssertionConsumer,
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/saml-response-parameter",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: a SAMLResponse where a SAMLRequest is expected",
			Retrieved: "2026-09-11",
		},
		// A perfectly good AuthnRequest sent as `SAMLResponse=` is
		// `Invalid Request`, the same 3572 bytes an empty request gets - so
		// this endpoint reads `SAMLRequest` and nothing else on the way in.
		// Measured beside it: a request carrying **both** parameters is served
		// from the SAMLRequest, which is what says one wins rather than the
		// pair being refused.
		//
		// The golden is byte-identical to no-parameters'. It is a case because
		// it is a **different input**: a handler reading whichever parameter is
		// present would answer this one past the floor of the ladder, and
		// nothing else in this chapter would notice.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "saml-service-provider-unsigned",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: "SAMLResponse=" + probeAuthnRequestNoAssertionConsumer,
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/redirect-binding-signature-accepted",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: a correctly signed AuthnRequest",
			Retrieved: "2026-09-11",
		},
		// **The positive control, and the case without which this chapter's
		// signature check is untestable.**
		//
		// AGENTS.md's mutation rule says a set of assertions an incorrect
		// implementation satisfies entirely is the failure shape to look for,
		// and a signature verifier is the worst version of it: a verifier that
		// refuses everything passes every case whose inputs are all rejections.
		// Every other signature case in this chapter is a rejection. This one
		// is not.
		//
		// The request is a genuinely signed HTTP-Redirect binding message -
		// RSA-SHA256 over `SAMLRequest=…&SigAlg=…`, with the signature
		// appended - from a client whose `saml.signing.certificate` the fixture
		// **pins**, so the whole thing is a literal and no key is minted at run
		// time. That is the second half of why F175's Fixture.SAMLRequests was
		// not built: a fixture can spell a key, so the catalogue can spell a
		// signature over it.
		//
		// The expected answer is `Invalid Request` with the client named, not a
		// 200: the message carries no Destination, and **a request carrying a
		// Signature parameter is required to have one** - measured 2026-09-11,
		// and the reason this case can be a literal at all. So the signature
		// verifying is exactly what moves it off `Invalid requester` and onto a
		// sentence one rung higher, on a body that is port-independent.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "saml-signed-client",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: probeAuthnRequestSignedQuery,
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/redirect-binding-signature-over-another-message",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: a valid signature attached to a different AuthnRequest",
			Retrieved: "2026-09-11",
		},
		// The negative control, and the half a "signature present" check would
		// pass. The `Signature` parameter here is the **same bytes** the case
		// above sends and verifies; the SAMLRequest under it is a different
		// message from the same client. Keycloak answers `Invalid requester`.
		//
		// The pair is what makes the check testable in both directions: an
		// implementation that verified nothing and looked only for the
		// parameters would pass the case above and fail this one; one that
		// refused everything would pass this one and fail that.
		//
		// Measured beside it and not recorded, because the bytes are this
		// golden's: a junk SigAlg and Signature, a SigAlg with no Signature, a
		// Signature with no SigAlg, and a SigAlg naming rsa-sha256 with a
		// SHA-512 signature under it, all answer this same page.
		//
		// Implemented since 2026-09-11 by handler.samlEndpoint.
		Status:  Implemented,
		Fixture: "saml-signed-client",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: probeAuthnRequestSignatureOverAnotherMessage,
		},
		AssertHeaders: []string{"Cache-Control", "Content-Language", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/logout-request-redirect",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML single logout: a LogoutRequest over the HTTP-Redirect binding",
			Retrieved: "2026-09-11",
		},
		Status:  Recorded,
		Fixture: "saml-service-provider-unsigned",
		Reason: "**New surface, and the first LogoutRequest anyone has sent at this " +
			"project.** The first cut enumerated 72 pairs and said in as many words that " +
			"none of them was a LogoutRequest, because the endpoint's three sentences are " +
			"decided by the Issuer before the message type is read. Measured 2026-09-11: " +
			"a LogoutRequest walks the **identical** ladder - Invalid Request, Login " +
			"requester not enabled, Bearer-only…, Wrong client protocol., Invalid " +
			"requester, and the Destination check - and diverges only at the top, where " +
			"an AuthnRequest gets the login page and this gets a 500: " +
			"`{\"error\":\"unknown_error\",\"error_description\":\"For more on this error " +
			"consult the server log.\"}`, 94 bytes, application/json, Cache-Control " +
			"no-store, must-revalidate, max-age=0, and **none** of the five security " +
			"headers - which makes this the first JSON body measured carrying that " +
			"endpoint's header set. Two requests gave identical bytes. " +
			"It is Recorded and not served on purpose. That 500 is Keycloak failing to " +
			"log out a **session that does not exist**, and a handler sending it whenever " +
			"a LogoutRequest arrives would answer 500 to a logout that ought to succeed - " +
			"which is the shape the first cut of this chapter refused, one message type " +
			"across. Gloak has no SAML session to end, so handler.samlEndpoint walks " +
			"every rung and then answers the dispatcher's `HTTP 404 Not Found`. " +
			"Serving it needs a SAML session store and an assertion builder: see F227.",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: "SAMLRequest=" + probeLogoutRequestRedirect,
		},
		AssertHeaders: []string{"Cache-Control", "Content-Type"},
		AssertAbsentHeaders: []string{
			"Content-Language",
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/endpoint/logout-request-post",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML single logout: a LogoutRequest over the HTTP-POST binding",
			Retrieved: "2026-09-11",
		},
		Status:  Recorded,
		Fixture: "saml-service-provider-unsigned",
		Reason: "The same LogoutRequest over the other binding, and **the two 500s are not " +
			"the same response**. This one is 500 with an **empty body**, no Content-Type " +
			"at all and `Cache-Control: no-cache`, where the redirect binding's carries " +
			"94 bytes of JSON, `application/json` and `no-store, must-revalidate, " +
			"max-age=0`. One path, one message, one failure, two verbs, two shapes - so " +
			"the verb split this endpoint has in its Cache-Control reaches the body as " +
			"well, which is not something the six 400 pages could have shown. " +
			"Recorded for its sibling's reason: the 500 is a session that does not exist " +
			"failing to end, not an answer a server without SAML sessions may send. " +
			"See F227.",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/saml",
			Form:   map[string]string{"SAMLRequest": probeLogoutRequestPOST},
		},
		AssertHeaders: []string{"Cache-Control"},
		AssertAbsentHeaders: []string{
			"Content-Language",
			"Content-Security-Policy",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},

	// -------------------------------------------------------------- IdP-initiated

	{
		ID: "saml/idp-initiated/unclaimed-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "IdP-initiated SSO: GET /realms/{realm}/protocol/saml/clients/{name}",
			Retrieved: "2026-09-07",
		},
		// `Client not found.`, 3574 bytes, with **all six** headers - the five
		// security ones and a Content-Security-Policy - where the 400 page on
		// /protocol/saml one segment up carries none of them. Same status, same
		// template, same container, opposite header sets.
		//
		// Implemented since 2026-09-11 by handler.samlIdPInitiated.
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/saml/clients/gloak-probe-no-such-sso-name",
		},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Language",
			"Content-Security-Policy",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/idp-initiated/client-id-is-not-the-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "IdP-initiated SSO: the path segment is not a clientId",
			Retrieved: "2026-09-07",
		},
		// The distinguishing input of this family. A **real, enabled SAML
		// client** addressed by its own clientId answers `Client not found.`,
		// because the segment is the client's saml_idp_initiated_sso_url_name
		// attribute and not its id. Without this row the case above and the one
		// below are both satisfied by a handler that looks clients up by
		// clientId: it would answer the unclaimed name correctly by accident
		// and this one wrongly with nothing to say so.
		//
		// Implemented since 2026-09-11 by handler.samlIdPInitiated.
		Status:  Implemented,
		Fixture: "saml-service-provider",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/saml/clients/gloak-probe-saml-sp",
		},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Language",
			"Content-Security-Policy",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/idp-initiated/claimed-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "IdP-initiated SSO: a name a client claims",
			Retrieved: "2026-09-07",
		},
		// The client resolves here and the answer moves to
		// `Invalid redirect uri`, 3607 bytes, which is what proves the attribute
		// is the lookup key.
		//
		// **The client here does carry a registered redirectUris pattern and is
		// refused anyway**, so the missing value is a SAML assertion consumer
		// URL and not a redirect URI. Re-measured 2026-09-11 from the other
		// side: setting `saml_assertion_consumer_url_post` on this same client,
		// with its redirectUris left exactly as they are, answers 200 with the
		// login page. So the two sources are separate and this case pins which
		// one this route reads.
		//
		// It is also where this route's boundary is: past it Keycloak posts a
		// signed assertion and Gloak has no assertion builder, so
		// handler.samlIdPInitiated answers the dispatcher's `HTTP 404 Not Found`
		// there rather than this page.
		//
		// Implemented since 2026-09-11 by handler.samlIdPInitiated.
		Status:  Implemented,
		Fixture: "saml-service-provider",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/saml/clients/gloak-probe-sso",
		},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Language",
			"Content-Security-Policy",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},

	{
		ID: "saml/idp-initiated/disabled-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "IdP-initiated SSO: a name a disabled client claims",
			Retrieved: "2026-09-11",
		},
		// **One client, two routes, two sentences for one state.** A disabled
		// client is `Client disabled.` here - 3573 bytes, with a full stop -
		// and `Login requester not enabled` on /protocol/saml one path segment
		// up, with none. The two routes disagree about the header set on the
		// same page as well, which saml/endpoint/disabled-client's declarations
		// and this one's spell out side by side.
		//
		// The check runs before the protocol one: this client's protocol is
		// `saml`, and its enabled flag is what answers, but a **disabled
		// openid-connect** client carrying the same kind of attribute was
		// measured answering `Client disabled.` too rather than
		// `Wrong client protocol.`, so the order is enabled-then-protocol on
		// this route as on the endpoint.
		//
		// Implemented since 2026-09-11 by handler.samlIdPInitiated.
		Status:  Implemented,
		Fixture: "saml-idp-initiated-clients",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/saml/clients/gloak-probe-sso-disabled",
		},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Language",
			"Content-Security-Policy",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "saml/idp-initiated/wrong-protocol",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "IdP-initiated SSO: a name an openid-connect client claims",
			Retrieved: "2026-09-11",
		},
		// **The name is looked up across protocols**, which is the cell that
		// says the protocol check is a rung of its own here rather than part of
		// the lookup. An enabled `openid-connect` client carrying
		// saml_idp_initiated_sso_url_name answers `Wrong client protocol.`
		// (3579 bytes) and not `Client not found.` (3574).
		//
		// A handler filtering the scan by protocol - the obvious
		// implementation, and the one that reads as a safety improvement -
		// answers `Client not found.` here, and the other three cases in this
		// family cannot see the difference.
		//
		// Implemented since 2026-09-11 by handler.samlIdPInitiated.
		Status:  Implemented,
		Fixture: "saml-idp-initiated-clients",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/saml/clients/gloak-probe-sso-oidc",
		},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Language",
			"Content-Security-Policy",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},

	// -------------------------------------------------------- artifact resolution

	{
		ID: "saml/artifact-resolution/request-denied",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "Artifact resolution service: POST /realms/{realm}/protocol/saml/resolve",
			Retrieved: "2026-09-07",
		},
		Status:  Pending,
		Fixture: "bootstrap",
		Reason: "**Measured and it cannot be a golden.** POST with a SOAP ArtifactResolve " +
			"answers 200 text/xml, 631 bytes, a samlp:ArtifactResponse whose status is " +
			"RequestDenied - and it carries ID=\"ID_<uuid>\" and an IssueInstant stamped " +
			"to the millisecond, both minted per request. Two requests six milliseconds " +
			"apart differed in exactly those two attributes and nowhere else. F113's rule " +
			"is that a body carrying a per-request value cannot be Recorded whatever else " +
			"is true of it, and VolatileXMLText does not rescue it: the ID is an " +
			"**attribute**, that frame is text-only, and building an attribute frame for " +
			"a body that may not be Recorded anyway would be a mask with no consumer. " +
			"Two measurements are kept here rather than in a golden. The response carries " +
			"four of the five security headers, omitting X-Frame-Options, where the " +
			"descriptor's application/xml carries all five - so **two XML media types one " +
			"path segment apart answer that rule differently**. And the request's " +
			"Content-Type is not read at all: text/xml, application/soap+xml and none " +
			"give the identical answer.",
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/realms/master/protocol/saml/resolve",
			Headers: map[string]string{"Content-Type": "text/xml"},
			Body:    []byte(probeArtifactResolve),
		},
	},
	{
		ID: "saml/artifact-resolution/empty-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "Artifact resolution service: an empty request body",
			Retrieved: "2026-09-07",
		},
		Status:  Recorded,
		Fixture: "bootstrap",
		Reason: "The half of the resolve endpoint that **can** be a golden: an empty body " +
			"is 500 {\"error\":\"unknown_error\",...} with all five security headers and " +
			"nothing per-request in it. It is here so the endpoint is not represented in " +
			"the catalogue by an unrecordable case alone - a chapter whose only evidence " +
			"is a Reason string is a chapter nobody can check. Gloak serves nothing here.",
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/realms/master/protocol/saml/resolve",
			Headers: map[string]string{"Content-Type": "text/xml"},
			Body:    []byte(" "),
		},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
}

// The literals below were generated once and verified against a live Keycloak
// 26.7.1 on 2026-09-11 before being written here: every one of them was sent to
// the container with the fixture that names it, and the sentence it came back
// with is the sentence its case asserts.
//
// They are literals rather than something computed at run time, and that is the
// harness's rule rather than a shortcut: a Step sends bytes and evaluates
// nothing. What makes the literals possible at all is one measurement - **an
// AuthnRequest needs no Destination** - which takes the server's own port out of
// the message. See F175 in the follow-ups for what that refuted.

// samlSignedClientCertificate is the X.509 certificate of the key
// saml/endpoint/redirect-binding-signature-accepted's signature was made with:
// DER in standard base64, no PEM armour, which is the spelling
// `saml.signing.certificate` takes.
//
// **Pinning it is what makes a signed request spellable in a catalogue.** The
// fixture installs this certificate on the client, the two queries below were
// signed offline with the matching private key, and nothing is minted at run
// time on either side. The private key is deliberately **not** here: nothing
// needs it, and a signature is checked with the public half.

const samlSignedClientCertificate = "MIICvzCCAaegAwIBAgIBATANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQDExdnbG9hay1wcm9i" +
	"ZS1zYW1sLXNpZ25lZDAgFw0yNjAxMDEwMDAwMDBaGA8yMTI2MDEwMTAwMDAwMFowIjEgMB4G" +
	"A1UEAxMXZ2xvYWstcHJvYmUtc2FtbC1zaWduZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw" +
	"ggEKAoIBAQD6I7XO9q4uEGy5oXcCjQmte2EIg5yigqSXrsB0Y8wUJkpkuAs6eDLjg7vgh7y9" +
	"tRF70Wc1kfN11qVwcsp8MdFxQRbumTR7qv8IKetoDrhDoBnzdxRoEJyd69JzGChBT328282D" +
	"QaXnP0p2wt3r6bZqnF7rteJl7ne3+WXkNoSTM3DjvZ9Eeb7ySNqL2XMFbRmPInf4St5GikB1" +
	"4BbJ0aQK8uud5Ck6+vwF2qGLzoEgXJ0TgOkNPtL1C+ITSidoy2FC7A4MyGhUHOagsFhdcmgF" +
	"F3/Ffvt0g9RetSXHzSvTKS1kzCKup7FA0rP0EqCrwhKi3XS3CFc5VJx3Ytv5Oc8JAgMBAAEw" +
	"DQYJKoZIhvcNAQELBQADggEBACdyE4qZ1JsPPY7y8AxCyyH3eNSNxGZ/PrcUkQwmkvHHoiQc" +
	"wpAWaW2x8b3shHPwHR/xf4ZXhWd0g/4VnSxAvXotE7m26Qp7X6byrN/anhUDtKwpY6EOVmgD" +
	"FpD8cpFyFh+N9MNUMAYvfcp7VVFckILeHUlqx9aqYkWHNfCiQnNzJQW+orHiP9yJ1mEz1aDn" +
	"2UHlIlg/GKIuOvTJpl7DKi/9OPIsW979RDf9Vw4KVqDQiFpUKLkS/Dhk7q1wuCQgpNynBqhW" +
	"KUmjirionW5wFIphFzzmMRnpctvDyoFjy+psZ6TM3SE4lFzRRRVfNdkaxnOjB4dmlMy/4Sh6" +
	"KDCQm+M="

const probeAuthnRequestSignedQuery = "SAMLRequest=fI%2FBSgQxDIZfZci9a6YHwbAzsLCXgl5UPHhZ6hrWYicZmxZ8fLFexssek%" +
	"2FzfR%2F69xSWvdGj1Qx75q7HV4XvJYtQPE7QipNGSkcSFjeqZng4P9%2BR3SGvRqmfNsEGu" +
	"E9GMS00qMITjBOF4umSNn6e16BvD8MLFksoEfocwBLPGQaxGqRN49LcO79w4Po%2BeEAnxFe" +
	"b%2BP%2FVkmbvLdZf73TtLF%2BH3%2Fc029Df9rzz%2FBAAA%2F%2F8%3D&SigAlg=http%3" +
	"A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=IeO%" +
	"2FBHFIDpp%2Fkyzpu7aEgyGZmiHj1BTup178wY7j2lRhjDpBBDdLcI0%2FgIKLu8Zb7Lrsuz" +
	"ocFi7YP5ivFAT9SQbng7sBhMw%2FxP3nA6jCo9hTfzi2g0ynlZxy9%2FTXKN%2F90JPLrAde" +
	"%2BMK%2FHSivW2D%2FCW3tLC%2FFSlP0g9l8lOd44HUnDEdwboTiEwv4jaSTpdkw8AQ9D5ii" +
	"vyR9eZr1IgObbLOvR8YxaStNEc6uuu95P6wubdptB7yT4McO1k53Y40lkZkJ4GZi1aBDMUU7" +
	"rUcqkfclcEULlF7rFTNvLOTUBs6GNsBQtvO7Gzaevl8VALKWa8lBvPGgmBP6dzG5eEVqgg%3" +
	"D%3D"

const probeAuthnRequestSignatureOverAnotherMessage = "SAMLRequest=fI%2FBSgNBDIZfZcl9anYOgqG7UOhlQC8qIl7KWEMdnE3WyQz4%2BNLxUi89" +
	"Jvm%2Fj%2Fxbi0teadfqpzzyd2Orw8%2BSxagfJmhFSKMlI4kLG9UjPe0e7slvkNaiVY%2Ba" +
	"4QK5TkQzLjWpwBD2E4T94ZQ1fh3Wou%2BvMLxwsaQygd8gDMGscRCrUeoEHv2twzs3js%2Bj" +
	"J0RCfIO5%2F089WebucmcXu%2FPeWToJf2xvLkN%2F0%2F%2FK828AAAD%2F%2Fw%3D%3D&S" +
	"igAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Si" +
	"gnature=IeO%2FBHFIDpp%2Fkyzpu7aEgyGZmiHj1BTup178wY7j2lRhjDpBBDdLcI0%2FgI" +
	"KLu8Zb7LrsuzocFi7YP5ivFAT9SQbng7sBhMw%2FxP3nA6jCo9hTfzi2g0ynlZxy9%2FTXKN" +
	"%2F90JPLrAde%2BMK%2FHSivW2D%2FCW3tLC%2FFSlP0g9l8lOd44HUnDEdwboTiEwv4jaST" +
	"pdkw8AQ9D5iivyR9eZr1IgObbLOvR8YxaStNEc6uuu95P6wubdptB7yT4McO1k53Y40lkZkJ" +
	"4GZi1aBDMUU7rUcqkfclcEULlF7rFTNvLOTUBs6GNsBQtvO7Gzaevl8VALKWa8lBvPGgmBP6" +
	"dzG5eEVqgg%3D%3D"

const probeAuthnRequestDisabledClient = "fI%2FBSgQxDIZfZci9a6YHwbAzsLCXgl5UPHhZurtBi51kbFrw8cV6GS8ek%2FzfR%2F69xS" +
	"WvdGj1XR75s7HV4WvJYtQPE7QipNGSkcSFjeqFng4P9%2BR3SGvRqhfNsEH%2BJ6IZl5pUYA" +
	"jHCcLx9JY1fpzWomeG4YWLJZUJ%2FA5hCGaNg1iNUifw6G8d3rlxfB49IRLiK8z9f%2BrJMn" +
	"eX6y73s3fXZPGc%2Bbq%2F2cZ%2Bp7%2Bl5%2B8AAAD%2F%2Fw%3D%3D"

const probeAuthnRequestBearerOnlyClient = "fI%2BxSgRBDIZfZUk%2FZ3YKwXC7cHDNgDYqFjbH3BF0cTZZkxnw8cWxORvLJP%2F3kX%2Fv" +
	"eS0bHVp9l0f%2BbOx1%2BFqLOPXDBM2ENPviJHllp3qhp8PDPcUd0mZa9aIFrpD%2FiezOVh" +
	"cVGNJxgnQ8vRXNH6fN9MwwvLD5ojJB3CEMyb1xEq9Z6gQR423AuzCOz2MkREJ8hbn%2FTz1p" +
	"c3eF7go%2F%2B3DmbGz7m%2BvQ7%2FS38vwdAAD%2F%2Fw%3D%3D"

const probeAuthnRequestWrongDestination = "fJDPSsRADIdfpcy9O9MeZA3bwkIvBb2oePCyxBq2xWlSJxnw8WVHhPWyx%2Fz5yJffQXGNGx" +
	"yzzfxEX5nUqu81skIZdC4nBkFdFBhXUrAJno%2BPD9DuAmxJTCaJ7gq5TaAqJVuEXTUOnRuH" +
	"0zkKfp62JO%2FkqldKugh3rt0FV42qmUZWQ7bOtaG9q8N93TQvTQshQAhvrhpIbWG0Qs1mG3" +
	"gfZcI4ixrswz74RBhX9SuqUfJ%2Fzv4i6%2FryP5RLqS8udXGpL%2F06sy5npo%2BDv177rf" +
	"6H1v8EAAD%2F%2Fw%3D%3D"

const probeAuthnRequestNoAssertionConsumer = "fI%2FBSgQxDIZfZci9a6YHwbAzsLCXgl5UPHhZ6hrWYicZmxZ8fLFexssek%2FzfR%2F69xS" +
	"WvdGj1Qx75q7HV4XvJYtQPE7QipNGSkcSFjeqZng4P9%2BR3SGvRqmfNsEGuE9GMS00qMITj" +
	"BOF4umSNn6e16BvD8MLFksoEfocwBLPGQaxGqRN49LcO79w4Po%2BeEAnxFeb%2BP%2FVkmb" +
	"vLdZf73bsmli7C7%2Fubbexv%2Bl96%2FgkAAP%2F%2F"

const probeAuthnRequestUnregisteredAssertionConsumer = "fJC9TsNADIBfJfKe5pqBCKuJFNElUllaYGCpjmA1ERc7nH2Ix0ccQioLo38%2B%2B7N36pew" +
	"Yp9s4iO9J1IrPpfAirnQQoqM4nVWZL%2BQoo146u8PWG8crlFMRglwhfxPeFWKNgtDMexbGP" +
	"bnSxD%2Fdl6jvBAUTxR1Fm6h3jgoBtVEA6t5thZqV9%2BU7rbcbh%2B2NTqHzj1D0f8OvBPW" +
	"tFA8UfyYR3o8HlqYzFasqiCjD5OoYdM0TeVHhS7fjXlD7LJDmR3K73yZWOcL0%2Buuum77if" +
	"4%2Bq%2FsKAAD%2F%2Fw%3D%3D"

const probeAuthnRequestLoginPage = "fJBNS%2FRADID%2FSsm922kPLzRsC%2BXdS2G97KoHL8tYw7Y4TeokI%2F58cURYLx7z8SRP" +
	"sle%2Fhg2HZDOf6C2RWvGxBlbMhQ5SZBSviyL7lRRtwvNwd8Rm53CLYjJJgBvkb8KrUrRFGI" +
	"rx0MF4uFyD%2BNfLFuWZoHikqItwB83OQTGqJhpZzbN10LjmX%2Bnasq7v6wadQ%2BeeoBh%" +
	"2BBv4X1rRSPFN8XyZ6OB07mM02rKogkw%2BzqGHbtm3lJ4U%2B3415Q%2ByzQ5kdyq98mViX" +
	"K9PLvrpt%2B45%2BP6v%2FDAAA%2F%2F8%3D"

const probeLogoutRequestRedirect = "fJDBSsQwEIZfpcy9Nc1BcNgWhV4CqwcVD16WWIdSTGZqJoF9fDG7h%2BLB48x83w%2FzH9TH" +
	"sOFRFin5mb4LaW7OMbBivQxQEqN4XRXZR1LMM748PB7Rdga3JFlmCbBT%2Fje8KqW8CkPjpg" +
	"HcdFqC%2BK%2FTluSDoHmjpKvwALYz0DjVQo41e84DWGNvW3PX9v1rb9EYNOYdxvoAVjKNNa" +
	"utWe3vvi2s68L0ebjZYxfnyUdy0965p7OPW6Bulng1rtBl%2BtPT%2BBMAAP%2F%2F"

const probeLogoutRequestPOST = "PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpT" +
	"QU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6" +
	"Mi4wOmFzc2VydGlvbiIgSUQ9IklEX2dsb2FrX3Byb2JlIiBWZXJzaW9uPSIyLjAiIElzc3Vl" +
	"SW5zdGFudD0iMjAyNi0wOS0xMVQxMjowMDowMFoiPjxzYW1sOklzc3Vlcj5nbG9hay1wcm9i" +
	"ZS1zYW1sLXVuc2lnbmVkPC9zYW1sOklzc3Vlcj48c2FtbDpOYW1lSUQ+Z2xvYWstcHJvYmVA" +
	"ZXhhbXBsZS5jb208L3NhbWw6TmFtZUlEPjwvc2FtbHA6TG9nb3V0UmVxdWVzdD4="

// The three AuthnRequests below are one message with three Issuers, and the
// Issuer is the only thing that differs between them. That is deliberate: the
// endpoint's three sentences are a ladder over the Issuer, so three requests
// differing in anything else could not say which rung the answer came from.
//
// They are literals rather than something computed at run time, and that is the
// harness's rule rather than a shortcut: a Step sends bytes and evaluates
// nothing. The plaintext of each is
//
//	<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
//	    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
//	    ID="ID_gloak_probe" Version="2.0" IssueInstant="2026-09-07T12:00:00Z"
//	    Destination="http://localhost:8080/realms/master/protocol/saml"
//	    AssertionConsumerServiceURL="http://localhost:9999/acs">
//	  <saml:Issuer>ISSUER</saml:Issuer>
//	</samlp:AuthnRequest>
//
// **The Destination naming port 8080 does not make these fragile**, and that was
// checked rather than assumed: the same request was sent with the container's
// real port in the Destination and with 8080, and both gave the identical
// answer. Keycloak reaches all three of these rungs before it looks at the
// Destination - the check runs after the signature, which none of these three
// passes - so the bytes are stable on whatever port testcontainers maps. The
// one request that does depend on the port is saml/endpoint/login-page, and
// that is exactly why it is Pending.

// probeAuthnRequestUnregistered names an Issuer no client carries: the ladder's
// floor, `Invalid Request`. DEFLATE with no zlib header, base64, percent-encoded,
// which is what the HTTP-Redirect binding carries.
const probeAuthnRequestUnregistered = "fZBPT8MwDMW%2FSpV7SegBNqutVNFLpXHZgAOXKWTWWpE%2FJXYQH5%2B0aNKQEFYujt97%2BTk1" +
	"aWdn6BKPfo8fCYmLL2c9wTpoRIoegqaJwGuHBGzg0D3uoLpRMMfAwQQrriz%2FOzQRRp6C" +
	"F8XQN2Loj2cb9PsxJ72hKF4wUh42Imuzgijh4Im153ylqrtSbUt1%2F3RbgVL5vIqiz8CT" +
	"17y6RuYZpLTBaDsGYtiojZIRtXUknSbGKC%2FMcoEVRXcBegieksN4wPg5GXze7%2F7I2%2B" +
	"aS2pBo68UOK2Fs1x3KdYcy%2BYjnaXkKTyXNtbwW%2FnS%2Fv7v9Bg%3D%3D"

// probeAuthnRequestOIDCClient names `account`, a bootstrapped openid-connect
// client every install has: the ladder's second rung, `Wrong client protocol.`
// It needs no fixture, which is why `account` was chosen over a created one.
const probeAuthnRequestOIDCClient = "fZBPSwNBDMW%2FyjL3OuMetA3bhcW9LNRLqx68lDiE7uL8WScZ8eM7XSlUEEMuyXsv%2FEjD" +
	"6N0MXZYx7OkjE0v15V1gWIStyilARJ4YAnpiEAuH7nEH9Y2BOUWJNjp1Ffk%2FgcyUZIpB" +
	"VUO%2FVUN%2FPLmI78dy6Y1U9UKJi7hVxVsczJmGwIJBysrUdyuzWZn7p9sajCn9qqq%2B" +
	"AE8BZUmNIjNo7aJFN0YWWJu10YnQedYeWSjpC7M%2Bw6qquwA9xMDZUzpQ%2BpwsPe93f9" +
	"zblNJoWbXNOQ4LYWrR2piDNPp6%2BTP9fm37DQ%3D%3D"

// probeAuthnRequestSAMLClient names the fixture's own SAML client: the ladder's
// third rung, `Invalid requester`, which is the signature check refusing an
// unsigned request from a client that requires one.
const probeAuthnRequestSAMLClient = "fZA9a8NADIb%2FirnduauHNBG2wdSLIV2StkOXoBoRm96He5JLf37PLoEUSoUWSe8rHqlk" +
	"dHaCZpbBH%2BljJpbsy1nPsA4qNUcPAXlk8OiIQXo4NY8HKDYGphgk9MGqG8v%2FDmSmKG" +
	"PwKuvaSnXt%2BWIDvp%2FTpjdS2QtFTsNKJW1SMM%2FUeRb0klqm2OZmn5v7p7sCjEn5qr" +
	"I2AY8eZXUNIhNobUOPdggssDM7oyOhdawdslDUV2a9wKqsuQI9BM%2Bzo3ii%2BDn29Hw8" +
	"%2FLFvn0Jjz6ouFzushLFeb8jXG%2FKln%2FNU6lvBT%2FX7zfU3"

// probeAuthnRequestPOSTBinding is the SAML client's request as the HTTP-POST
// binding carries one: base64 of the raw XML, **not** deflated, and not
// percent-encoded either because url.Values.Encode does that. The two bindings
// differ in exactly the compression and each rejects the other's encoding, which
// is why both spellings are here rather than one being reused.
const probeAuthnRequestPOSTBinding = "PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6" +
	"Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNz" +
	"ZXJ0aW9uIiBJRD0iSURfZ2xvYWtfcHJvYmUiIFZlcnNpb249IjIuMCIgSXNzdWVJbnN0YW50PSIy" +
	"MDI2LTA5LTA3VDEyOjAwOjAwWiIgRGVzdGluYXRpb249Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9y" +
	"ZWFsbXMvbWFzdGVyL3Byb3RvY29sL3NhbWwiIEFzc2VydGlvbkNvbnN1bWVyU2VydmljZVVSTD0i" +
	"aHR0cDovL2xvY2FsaG9zdDo5OTk5L2FjcyI+PHNhbWw6SXNzdWVyPmdsb2FrLXByb2JlLXNhbWwt" +
	"c3A8L3NhbWw6SXNzdWVyPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg=="

// probeArtifactResolve is a SOAP 1.1 envelope carrying a SAML ArtifactResolve,
// which is what the artifact resolution service reads. The artifact is not a
// real one; the endpoint answers RequestDenied for any artifact it cannot
// redeem, which is every artifact on a server nobody has logged in to.
const probeArtifactResolve = `<?xml version="1.0"?><SOAP-ENV:Envelope ` +
	`xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>` +
	`<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
	`ID="ID_gloak_probe" Version="2.0" IssueInstant="2026-09-07T12:00:00Z">` +
	`<Artifact xmlns="urn:oasis:names:tc:SAML:2.0:protocol">AAQAA</Artifact>` +
	`</samlp:ArtifactResolve></SOAP-ENV:Body></SOAP-ENV:Envelope>`

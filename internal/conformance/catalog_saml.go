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
		Status:    Implemented,
		Fixture:   "bootstrap",
		Operation: "GET /realms/{realm}/protocol/saml/descriptor",
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
		Operation:   "GET /realms/{realm}/protocol/saml/descriptor",
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
		ID: "saml/descriptor/unknown-protocol",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "IDP metadata descriptor: an unregistered login protocol",
			Retrieved: "2026-09-07",
		},
		Status:  Recorded,
		Fixture: "bootstrap",
		Reason: "Keycloak answers 404 {\"error\":\"Protocol not found\"} for any protocol " +
			"that is not registered, and Gloak has no protocol dispatcher to answer it " +
			"from: a path under /realms/{realm}/protocol/ that no route matches reaches " +
			"WithKeycloakFallbacks and gets the unmatched-path body with no security " +
			"headers. Measured 2026-09-07, and it is **not a SAML behaviour** - " +
			"/protocol/nosuchproto/certs and /protocol/nosuchproto answer the same " +
			"sentence - so it belongs to whoever builds the dispatcher rather than to " +
			"this chapter. It is here because this is the sweep that found it, and " +
			"because a spelling nothing records is a spelling the next cut re-measures.",
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
		Status:  Recorded,
		Fixture: "bootstrap",
		Reason: "Gloak has no route under /realms/{realm}/protocol/saml, so this reaches " +
			"the unmatched-path fallback. The page is not the missing half - its bytes " +
			"are here and it is reachable - the missing half is the ladder beside it: " +
			"this same endpoint answers three other sentences depending on the Issuer, " +
			"and the fifth rung is a login page.",
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
		Status:  Recorded,
		Fixture: "bootstrap",
		Reason: "A POST carrying an empty form answers the same 3572-byte page the GET " +
			"does, which is what says the two verbs are one handler here. It is worth a " +
			"case because /auth is the opposite: POST /auth reads the body and ignores " +
			"the query, so its two verbs answer differently to the same parameters, and " +
			"a reader generalising from that endpoint would expect a difference. Gloak " +
			"serves neither verb on this path.",
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
		Status:  Recorded,
		Fixture: "bootstrap",
		Reason: "The floor of the Issuer ladder, and the row without which the two cases " +
			"below prove nothing. A well-formed AuthnRequest whose Issuer names no " +
			"client answers the **same 3572 bytes** an empty request does, so the " +
			"endpoint's answers split on which client resolved rather than on whether a " +
			"message was read. Gloak has no route here.",
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
		Status:  Recorded,
		Fixture: "bootstrap",
		Reason: "The ladder's second rung: an Issuer naming a registered **openid-connect** " +
			"client is `Wrong client protocol.`, 3579 bytes, where an unregistered one is " +
			"3572 and a saml one is 3604. It uses the bootstrapped `account` client, so " +
			"the input needs no fixture and cannot drift. Gloak has no route here, and " +
			"would need a SAML message reader and the client's protocol to answer it. " +
			"Note the direction: the scope evaluator serves **both** protocols on one " +
			"route and refusing the mismatch there is wrong on four operations, while " +
			"here the mismatch is the answer.",
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
		Status:  Recorded,
		Fixture: "saml-service-provider",
		Reason: "The ladder's third rung, `Invalid requester`, 3604 bytes - and the reason " +
			"none of this chapter is served. It is not \"the client is unknown\": the " +
			"client resolved, and what failed is the **signature**. Every client " +
			"POST /clients creates with protocol saml carries " +
			"`saml.client.signature: \"true\"`, and turning it off makes this exact " +
			"request answer 200 with the login page. So serving this rejection means " +
			"either building XML signature verification or answering `Invalid requester` " +
			"to a properly configured client, which is the one request the endpoint " +
			"exists for.",
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
		Status:  Recorded,
		Fixture: "saml-service-provider",
		Reason: "The POST binding carries the AuthnRequest base64'd and **not** deflated, " +
			"which is the one thing about it a reader would get wrong from the GET case: " +
			"the same message deflated is unreadable here and the same message raw is " +
			"unreadable there, and both unreadable spellings fall to `Invalid Request`. " +
			"Measured to reach the identical 3604-byte page, so the two bindings agree " +
			"once the message is decoded and the difference is the transport alone. " +
			"Gloak reads neither encoding.",
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
		ID: "saml/endpoint/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "SAML endpoint: an unknown realm",
			Retrieved: "2026-09-07",
		},
		Status:  Recorded,
		Fixture: "bootstrap",
		Reason: "The realm is resolved before the request is read: an unknown realm answers " +
			"404 {\"error\":\"Realm does not exist\"} **with** the five security headers, " +
			"where the same path on master answers a page with none of them. Two " +
			"rejections on one path produced at different depths of one request, and the " +
			"deeper one is the one that loses the headers. Gloak has no route here, so " +
			"this reaches the unmatched-path fallback and answers the wrong body with no " +
			"headers at all.",
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
		ID: "saml/endpoint/unknown-subpath",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/saml/index",
			Section:   "A path under /protocol/saml that no route serves",
			Retrieved: "2026-09-07",
		},
		Status:  Recorded,
		Fixture: "bootstrap",
		Reason: "The discriminator this whole enumeration rests on, kept as a case so it is " +
			"checkable rather than asserted in a comment. A path under /protocol/saml/ " +
			"that no route serves answers {\"error\":\"HTTP 404 Not Found\"} with **all " +
			"five** security headers, where a path outside the realm tree answers " +
			"{\"error\":\"Unable to find matching target resource method\"} with none - " +
			"so the router reached its resource and found nothing to run. Gloak answers " +
			"the second body, which is the divergence and the reason this is Recorded. " +
			"It is the shape AGENTS.md records under /organizations, met on a second " +
			"family.",
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
		Reason: "**Measured, and unreachable by this harness for two independent reasons.** " +
			"An AuthnRequest from a client with saml.client.signature off, naming the " +
			"server's own URL as its Destination, answers 200 with the login page, 6869 " +
			"bytes - so the success path exists and is one attribute away. " +
			"First blocker: the Destination is validated, and it has to be the base URL " +
			"the server is actually reachable on. A Request carries literal bytes, the " +
			"AuthnRequest is DEFLATE-compressed and base64'd before it is a parameter, " +
			"and Expand rewrites Path, Query, Headers, Form and Body from **fixture " +
			"captures** with no issuer variable among them - so no literal request can " +
			"name the recorder's mapped port. That is F122's boundary met from a third " +
			"side, and the shape of the answer is DPoP's: Fixture.Proofs mints a value " +
			"the catalogue cannot spell, and a Fixture.SAMLRequests would have to do the " +
			"same. " +
			"Second blocker: the page carries a per-request tab_id, so it could not be " +
			"Recorded even if the request could be sent - F113 - and it is the tenth " +
			"page of the family AGENTS.md already records nine of. " +
			"It is Pending rather than absent because leaving it out would make this " +
			"chapter's denominator say the endpoint has only refusals, which is the " +
			"error the first reading of this endpoint actually made.",
		Request: Request{
			Method:   http.MethodGet,
			Path:     "/realms/master/protocol/saml",
			RawQuery: "SAMLRequest=" + probeAuthnRequestSAMLClient,
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
		Status:  Recorded,
		Fixture: "bootstrap",
		Reason: "Gloak has no route under /realms/{realm}/protocol/saml/clients/. The page " +
			"is `Client not found.`, 3574 bytes, with **all six** headers - the five " +
			"security ones and a Content-Security-Policy - where the 400 page on " +
			"/protocol/saml one segment up carries none of them. Same status, same " +
			"template, same container, opposite header sets.",
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
		Status:  Recorded,
		Fixture: "saml-service-provider",
		Reason: "The distinguishing input of this family. A **real, enabled SAML client** " +
			"addressed by its own clientId answers `Client not found.`, because the " +
			"segment is the client's saml_idp_initiated_sso_url_name attribute and not " +
			"its id. Without this row the case above and the one below are both satisfied " +
			"by a handler that looks clients up by clientId: it would answer the " +
			"unclaimed name correctly by accident and this one wrongly with nothing to " +
			"say so. Gloak has no route here either way.",
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
		Status:  Recorded,
		Fixture: "saml-service-provider",
		Reason: "The client resolves here and the answer moves to `Invalid redirect uri`, " +
			"3607 bytes, which is what proves the attribute is the lookup key. It is also " +
			"where this chapter's boundary is: the client resolved and Keycloak then " +
			"wants an assertion consumer URL to redirect to, so serving this rejection " +
			"without building that resolution would answer `Invalid redirect uri` to a " +
			"properly configured client - the request the whole route exists for. Note " +
			"the client here **does** carry a registered redirectUris pattern and is " +
			"refused anyway, so the missing value is a SAML assertion consumer URL and " +
			"not a redirect URI.",
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
			"is a Reason string is a chapter nobody can check. Gloak has no route here.",
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

package conformance

import "net/http"

// accountCases is the account REST API, enumerated by hand against a live
// Keycloak 26.7.1 on 2026-09-07 because nothing describes it: the vendored
// Admin API document does not reach it, and its chapter had carried "has not
// been enumerated" since the parity meter was built.
//
// # The discriminator is not the two 404s, and that is the first finding
//
// The SAML sweep one chapter over enumerated its surface with Keycloak's own
// pair of 404 bodies - an unmatched path answers `Unable to find matching
// target resource method` with none of the five security headers, a path the
// router knows answers `HTTP 404 Not Found` with all five. **That pair does
// not work here**, and it was checked in both directions before anything was
// built on it:
//
//	GET /realms/master/nosuchthing               404  HTTP 404 Not Found        5 of 5
//	GET /realms/master/account/nosuchsub         200  text/html, 4222 bytes     5 of 5
//
// Every path under `/realms/{realm}/account`, including ones no route serves,
// answers **200 with the account console's single-page application**, and the
// two 404 bodies never appear. A sweep run the SAML way would have concluded
// that the account surface is infinite.
//
// What decides is the request's `Accept` header, and the rule was measured over
// nineteen spellings on one path with one token:
//
//	application/json                          REST
//	APPLICATION/JSON                          REST     - the type folds case
//	application/json, text/plain, */*         REST
//	text/html,application/json                REST     - any position matches
//	text/html, application/json               REST     - the space is trimmed
//	*/*                                       console
//	application/*                             console  - a wildcard is not a match
//	application/ld+json                       console  - no +json suffix reading
//	application/json;charset=UTF-8            console  - a parameter disqualifies
//	application/json;q=1                      console  - **including q**
//	text/html;q=0.9,application/json;q=1.0    console  - so does a q on any entry
//	(no header at all)                        console
//	xyz                                       500 unknown_error
//
// So the REST resource is reached exactly when the parsed accept list contains
// the media type `application/json` **with no parameters at all**, and `q=1` -
// which is the default and changes nothing about the request's meaning -
// disqualifies it. A content negotiator that honoured q-values would route
// three of those rows the other way.
//
// This is also the measured answer to F155's question for this API. A
// mismatched `Accept` is a 406 across the Admin API; here it is a 200 with a
// different resource, and the only 406-shaped thing on the surface is nothing
// at all.
//
// # The enumeration: 16 route shapes, 112 verb cells, 40 counted behaviours
//
// **The three numbers in this heading disagreed with each other and with the
// slice until 2026-09-07.** The commit that added the chapter said 36, this
// heading said 41, the slice held 39, and a paragraph below said seventeen
// paths where the list above it has sixteen. Nothing could fail on any of them.
// TestAccountChapterCountIsThePinnedNumber now reads the slice, so the count in
// this sentence is the one a test asserts rather than the one a reader trusts.
//
// **The two-404 discriminator does not work on this surface, and the sentence
// that said it did was wrong.** It read: sweeping candidates with
// `Accept: application/json` "puts the two 404 bodies back". Re-measured on
// 2026-09-07, one container, one fully-privileged account user:
//
//	GET /realms/master/account/nosuchthing            404 HTTP 404 Not Found   5 of 5
//	GET /realms/master/account/credentials/bogus      404 HTTP 404 Not Found   5 of 5
//	GET /realms/master/nosuchthing                    404 HTTP 404 Not Found   5 of 5
//	GET /nosuchthingatall                             404 Unable to find …     0 of 5
//
// A path that exists and a path that does not answer the **same body with the
// same five headers**, and the unmatched-path body is not reachable anywhere
// under `/realms/`. That is exactly F184's shape, which this chapter sits
// inside; the SAML cut's method cannot be borrowed here, and the `Accept`
// header buys the JSON branch rather than the discriminator.
//
// What did the enumerating is weaker and had to be stated: **a route exists
// when at least one verb answers outside the generic fallback family** - a 200,
// a 204, a 400, a 403, a 415, a 500, or a 404 carrying its own sentence.
// `OPTIONS` is excluded from that test and the exclusion is load-bearing: it
// answers 200 with an empty body on **every** path including ones that do not
// exist, so it witnesses nothing. Sixteen route shapes answer it and no more:
//
//	/account                       the profile
//	/account/credentials
//	/account/credentials/{id}
//	/account/credentials/{id}/label
//	/account/credentials/{id}/moveToFirst
//	/account/credentials/{id}/moveAfter/{id}
//	/account/sessions
//	/account/sessions/devices
//	/account/sessions/{id}
//	/account/applications
//	/account/applications/{clientId}/consent
//	/account/groups
//	/account/linked-accounts
//	/account/linked-accounts/{alias}
//	/account/resources (and its five sub-paths, all behind one gate)
//	/account/supportedLocales
//
// Twenty-three candidates were tried and answered the generic 404 on every
// verb: `/totp`, `/password`, `/organizations`, `/profile`, `/attributes`,
// `/metadata`, `/devices`, `/consents`, `/roles`, `/realm`, `/logout`,
// `/login-redirect`, `/credentials/password`, `/user-profile-metadata` among
// them. "Answered the generic 404" is what they share with a route that exists,
// which is why the rejection rests on **no verb answering anything else**
// rather than on the body.
//
// Sixteen paths crossed with seven verbs is a 112-cell sweep, and the run of
// 2026-09-07 added a seventeenth path - `/account/nosuchthing` - as the
// control, which is where the 119 in the earlier draft came from. **Most of the
// sweep is the generic fallback family**: `HTTP 404 Not Found` and `HTTP 405
// Method Not Allowed`, which `http/fallback` already counts once for the whole
// API. Those cells are **not** in this chapter's denominator, the same decision
// the SAML cut made and for the same reason - counting them per path would
// report two behaviours ninety-odd times. Two cells that look like fallback
// are counted, because they are not it:
//
//   - `PATCH /account/resources` answers **403** where PATCH answers 405
//     everywhere else on this API, so the UMA gate beats the method dispatch;
//   - `OPTIONS` answers 200 with **no `Allow` header and no `Content-Type`**,
//     which is not the SAML family's OPTIONS and is not any 405.
//
// The full table is in docs/superpowers/handover/account-api.md.
//
// # The gate is two stages, and the statuses are the finding
//
// A caller whose token grants **no role on the realm's `account` client** is
// **401**, not 403. A caller past that stage holding the wrong account role is
// 403. And the first stage does not read the token's `aud` claim, which was
// measured rather than reasoned:
//
//	admin-cli token, user holding account roles      200   no aud claim
//	admin-cli token, user holding no roles at all    401   no aud claim
//	fullScopeAllowed=false client, full user         401   no aud claim
//	ordinary client, user holding account roles      200   aud: account
//
// Three of those four tokens carry no `aud` at all and they are not all
// answered the same way, so the gate reads the token's **granted** roles.
// `admin-cli` is a lightweight client, which is why its accepted token has no
// claim to read; `account/gate/scope-filtered-token` is the refused one.
//
// # The route role sets, swept one role at a time
//
// All eight of the `account` client's roles were assigned singly to a user
// stripped of `default-roles-master` and ten paths asked of each:
//
//	                        view-  manage-  manage-  manage-  view-  view-  view-  delete-
//	                        prof.  account  a-links  consent  apps   cons.  grps   account
//	/account                 200     200      403      403     403    403    403     403
//	/credentials             200     200      403      403     403    403    403     403
//	/sessions                200     200      403      403     403    403    403     403
//	/sessions/devices        200     200      403      403     403    403    403     403
//	/linked-accounts         200     200      403      403     403    403    403     403
//	/applications            403     200      403      403     200    403    403     403
//	/groups                  403     200      403      403     403    403    200     403
//	/applications/{c}/consent 403    204      403      204     403    204    403     403
//	/supportedLocales        200     200      200      200     200    200    200     200
//	/resources               403     403      403      403     403    403    403     403
//
// Three of those rows are why this cut serves two reads rather than one with a
// shared guard: `/groups` and `/linked-accounts` take **different** pairs, and
// `manage-account-links` - the one role whose name matches a route - opens
// nothing at all, `/linked-accounts` included. `/supportedLocales` takes no
// role and is the row that separates the audience gate from the role gate.
// `/resources` is refused to every role, because its realm gate runs first.
//
// # What is served and what is not
//
// Two reads: `/groups` and `/linked-accounts`, both pure functions of state
// Gloak already holds, plus the whole gate in front of them.
//
// `/supportedLocales` is **measured and deliberately not served**, and the
// reason is the one this project keeps naming rather than an estimate of
// effort. It answers the realm's stored `supportedLocales` in **stored order**,
// and `internationalizationEnabled` does not gate it - a realm with the flag
// off still answers its four locales, and a realm with locales `zz, de, en, fr`
// answers them unsorted. Gloak stores no supported locales at all;
// realmReducedRepresentation sends a constant `[]`. A handler here could
// therefore only return that constant, it would match a golden recorded against
// master, and it would be wrong on every realm that has locales. That is
// AGENTS.md's "a set of inputs an incorrect implementation satisfies entirely",
// and adding the case rather than the handler is what stops it being invisible.
//
// Everything else is Recorded: the profile read and its 500, the credentials
// family, the sessions family, the applications and consent family, the
// linked-accounts refusal, the UMA gate, the console branch, and the dispatch
// cells.
var accountCases = []Case{
	// ---------------------------------------------------------------- the gate

	{
		ID: "account/gate/no-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: bearer authentication",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/account/groups",
			Headers: map[string]string{"Accept": "application/json"},
		},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		// **No WWW-Authenticate.** userinfo puts its error there and this API
		// sends none at all, so the negative is declared: without it, an
		// implementation that added a bearer challenge "because a 401 should
		// have one" would look like a pass.
		AssertAbsentHeaders: []string{"WWW-Authenticate", "Cache-Control"},
	},
	{
		ID: "account/gate/garbage-bearer",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: bearer authentication",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer not-a-token",
			},
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
		// Byte-identical to the case above, which is the measurement: this API
		// does not tell a missing header from a bad token, where userinfo does.
		AssertAbsentHeaders: []string{"WWW-Authenticate"},
	},
	{
		ID: "account/gate/basic-credentials",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: bearer authentication",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept": "application/json",
				// The bootstrapped administrator's real credentials, which the
				// admin API would accept nowhere either. It is here because a
				// scheme this endpoint does not know has to answer the same 401
				// as no header at all, and `Basic` is the scheme a caller
				// actually sends by mistake.
				"Authorization": "Basic YWRtaW46YWRtaW4=",
			},
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/gate/lowercase-scheme",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: bearer authentication",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "account-user",
		// The positive control for the scheme, and it is a positive control on
		// purpose: the three cases above are all refusals, and a bearerToken
		// that returned "" for everything would pass all three. This one is the
		// same header spelled `bearer` in lower case and it answers 200 -
		// measured - so the fold is asserted in the direction that can fail.
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Cache-Control", "Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/gate/wrong-scheme",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: bearer authentication",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "account-user",
		// **A valid token under a scheme that is not Bearer.** The three
		// refusals above all send something that would fail verification
		// anyway, so a bearerToken that ignored the scheme entirely passed all
		// of them - measured as a surviving mutation, which is why this case
		// exists. `Negotiate`, `DPoP` and `Token` were all measured 401 with
		// the same token that answers 200 as `Bearer` and as `bearer`.
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Negotiate {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/gate/double-space-scheme",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: bearer authentication",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "account-user",
		// **Exactly one space separates the scheme from the token.** `Bearer`
		// followed by two spaces and a token that answers 200 with one space is
		// a 401 - measured, along with three spaces and a tab, which answer the
		// same way.
		//
		// It is here because the obvious implementation passes everything else:
		// a bearerToken that runs strings.TrimSpace over the part after the
		// first space answers 200 to this request, and every other case on this
		// API agrees with the correct one. bearerToken's doc comment named this
		// case and account/gate/leading-space-scheme beside it before either
		// existed; they exist now.
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer  {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/gate/disabled-user",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: bearer authentication",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "account-user-disabled",
		// A token that verifies, names a live session, and belongs to an
		// account that was disabled after it was issued. **401**, measured on
		// one user before and after the PUT: 200 while enabled and 401 after.
		// It is here because removing the enabled check survived every other
		// case in the chapter.
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/gate/realm-role-of-the-same-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: the account client audience",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "account-user-realm-role-collision",
		// **A realm role literally named `view-profile`, and no account role.**
		// 401, measured on all three of /groups, /linked-accounts and
		// /supportedLocales. It is internal/admin's F32 asked of this API: a
		// gate that matched the role's *name* would hand the whole account
		// surface to anybody who can mint a role, and every other case in this
		// chapter is blind to it because no other fixture creates a colliding
		// name. Found by a mutation that dropped the container test and
		// survived.
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/gate/no-account-roles",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: the account client audience",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "account-user-no-roles",
		// A real, verifiable, unexpired token for a live session, refused
		// **401**. This is the case that says the audience stage exists at all:
		// without it the whole gate reads as "authenticate, then check a role",
		// and every refusal in this chapter would be a 403.
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/gate/scope-filtered-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: the account client audience",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "the audience gate is measured on the token's granted scope, and Gloak's " +
			"token issuance does not implement fullScopeAllowed at all - the client's " +
			"filter is ignored, so the account roles the user really holds reach the " +
			"gate and Gloak answers 200 where Keycloak answers 401. It is a divergence " +
			"in internal/oidc's token path rather than in this package, and it is " +
			"recorded here because this is the request that exposes it",
		Fixture: "account-user-scope-filtered",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "account/gate/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: realm resolution",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		// **No Authorization header and no Accept.** Both omissions are the
		// point: the realm is resolved before the token and before the content
		// negotiation, so this request answers about the realm rather than 401
		// or the console page. Measured with all three Accept spellings.
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/nosuchrealm/account/groups",
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
		// The 200 beside it carries no-cache and this carries none, which is the
		// same split /realms/{realm}'s own 404 has.
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		ID: "account/gate/wrong-role-groups",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /groups authorization",
			Retrieved: "2026-09-07",
		},
		Status: Implemented,
		// view-profile opens /linked-accounts and is refused here, which is half
		// of what stops the two served reads sharing one guard.
		Fixture: "account-user-view-profile",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/gate/wrong-role-linked-accounts",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /linked-accounts authorization",
			Retrieved: "2026-09-07",
		},
		Status: Implemented,
		// view-groups opens /groups and is refused here. The two cases are the
		// pair: a single shared guard passes one of them and fails the other
		// whichever role set it is written with.
		Fixture: "account-user-view-groups",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/linked-accounts",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/gate/links-role-opens-nothing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /linked-accounts authorization",
			Retrieved: "2026-09-07",
		},
		Status: Implemented,
		// **`manage-account-links` is refused by the linked-accounts read.** It
		// is the one account role whose name matches this route, and a guard
		// written from the name alone admits the caller Keycloak refuses and
		// refuses the caller - view-profile - that it admits. Both directions
		// wrong from one plausible reading, which is why this case is separate
		// from the one above rather than folded into it.
		Fixture: "account-user-links-role",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/linked-accounts",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},

	// ---------------------------------------------------------------- groups

	{
		ID: "account/groups/none",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/groups",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
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
	},
	{
		ID: "account/groups/member",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/groups",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "account-user-grouped",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Cache-Control", "Content-Type", "X-Frame-Options"},
		// The group's id is minted by the fixture's own create and captured, so
		// ReplaceCaptured reaches it and nothing here needs masking. What the
		// golden asserts is the whole four-key shape - id, name, path,
		// subGroups - with **no `parentId`**, which is the half of the rule the
		// child case cannot show.
	},
	{
		ID: "account/groups/child-only",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/groups",
			Retrieved: "2026-09-07",
		},
		Status: Implemented,
		// **Membership does not reach upwards.** This user is in a child and in
		// nothing else, and the answer is one row: the child, carrying a
		// `parentId` naming a group that is not in the list. A handler that
		// expanded the ancestry - which is what "the groups I am in" invites -
		// answers two rows here and is right on every other case in this
		// chapter, because every other group in it is at the top of the realm.
		Fixture: "account-user-child-group",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Cache-Control", "Content-Type", "X-Frame-Options"},
		// The child's id is the fixture's capture; the parent's is not, because
		// the fixture overwrites group_id with the child's. So `parentId` is
		// masked and its **presence and position** stay asserted, which is the
		// half this case exists for.
		Volatile: []string{"*/parentId"},
	},

	// ------------------------------------------------------- linked accounts

	{
		ID: "account/linked-accounts/none",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/linked-accounts",
			Retrieved: "2026-09-07",
		},
		Status: Implemented,
		// **This listing enumerates the realm's identity providers, so it needs a
		// realm nothing else has touched.** Recorded against the shared
		// container it answered sixteen rows - every `gloak-probe-idp*`,
		// `gloak-probe-map-broker-*` and `gloak-probe-mt-broker-*` the admin
		// chapter's fixtures create in master before the account cases run - and
		// the `[]` this golden used to hold could only have come from a run that
		// recorded the account chapter alone.
		//
		// The hazard was known and defended on the wrong half of the pair.
		// accountBrokerFixture builds a realm of its own precisely "because four
		// identity providers in master would appear in every golden that
		// enumerates the realm's own"; the case that *creates* providers was
		// protected and the case that asserts there are **none** was left
		// addressing master. That is the shape this repository keeps meeting -
		// a rule right on one family and inverted on its neighbour - inside one
		// pair of sibling cases.
		//
		// The pollution guard could not see it: an identity provider is named by
		// `alias`, and createdKeys watches clientId, username, realm and name.
		// See F195.
		PristineRealm: true,
		Fixture:       "account-user",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/linked-accounts",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		// **No Cache-Control**, where the groups read one route away sends
		// `no-cache`. Six of the eight measured 200s on this API send it and
		// this is one of the two that do not, so the negative is declared: a
		// single JSON writer used by both reads would pass the groups case and
		// silently start sending a header here.
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		ID: "account/linked-accounts/providers",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/linked-accounts",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "account-user-brokers-unlisted",
		// Four providers, four separate refutations in one body - see
		// accountBrokerFixture. The disabled one is absent, the `google` one is
		// the only `"social": true`, the one with no display name falls back to
		// its alias, and the one whose alias sorts last carries a display name
		// that sorts first, so the order says the sort key is the alias.
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/gloak-probe-account-brokers/account/linked-accounts",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders:       []string{"Content-Type", "X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		ID: "account/linked-accounts/unknown-alias",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/linked-accounts/{alias}",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "the single linked account is the link-and-unlink pair, which needs a " +
			"federated identity link and a broker redirect neither this package nor " +
			"internal/oidc builds. Its refusal is measured and is worth recording on " +
			"its own: 400 {\"errorMessage\":\"identityProviderNotFoundMessage\"} - an " +
			"**unresolved i18n message key on the wire**, which is Keycloak's own " +
			"defect and is the contract",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/linked-accounts/nosuchalias",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// ------------------------------------------------------ supported locales

	{
		ID: "account/supported-locales/none",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/supportedLocales",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "Gloak stores no supported locales - realmReducedRepresentation sends a " +
			"constant [] and no realm field holds them - so a handler here could only " +
			"return that constant, would match this golden, and would be wrong on " +
			"every realm that has locales. Serving it needs a realm column and belongs " +
			"to admin/realms-admin; see the realm-locales case beside this one for " +
			"what it would have to answer",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/supportedLocales",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		ID: "account/supported-locales/realm-locales",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/supportedLocales",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "the same gap as the case above, and this is the request that shows what " +
			"it costs: the realm's locales come back in **stored order** rather than " +
			"sorted, and internationalizationEnabled does not gate them - measured " +
			"with the flag off and on, same four locales both ways",
		Fixture: "account-user-brokers",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/gloak-probe-account-brokers/account/supportedLocales",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// ---------------------------------------------------------------- profile

	{
		ID: "account/profile/read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "the body is the user plus a userProfileMetadata block - four attributes, " +
			"their validators and their annotations - which is the same derivation " +
			"GET /admin/realms/{realm}/users/profile/metadata performs and which " +
			"AGENTS.md records as a real derivation that a constant used to pass. " +
			"Serving it here means either sharing that serialiser, which the two " +
			"shapes are not measured to agree on, or writing a second one; both are a " +
			"cut of their own",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Cache-Control", "Content-Type", "X-Frame-Options"},
		Volatile:      []string{"id"},
	},
	{
		ID: "account/profile/post-no-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: POST /realms/{realm}/account",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "the profile write is behind the same userProfileMetadata derivation as " +
			"the read. Its empty-body answer is recorded on its own because it is a " +
			"**500**, not a 400 - the same defect family as POST /users with an empty " +
			"body, on a second API",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/account",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// ------------------------------------------------------------ credentials

	{
		ID: "account/credentials/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/credentials",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "the body is the realm's credential **provider metadata** - two entries, " +
			"password and otp, each with a category, an i18n display name and help " +
			"text, an icon class and a create or update action - and Gloak models " +
			"none of it. The user's own credential nests inside the first entry, so " +
			"this is a listing of what the realm can hold rather than of what the " +
			"user has",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/credentials",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Cache-Control", "Content-Type"},
		// The credential's id and createdDate are minted when the fixture's user
		// create stores the password, and neither is captured, so both are
		// masked while their presence and position stay asserted.
		Volatile: []string{
			"*/userCredentialMetadatas/*/credential/id",
			"*/userCredentialMetadatas/*/credential/createdDate",
		},
	},
	{
		ID: "account/credentials/delete-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: DELETE /realms/{realm}/account/credentials/{id}",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "the credential family's writes are not served. Its refusal is recorded " +
			"because the spelling is shared with the Admin API - `Credential not " +
			"found`, entry (5) of AGENTS.md's list - so this API adds no spelling of " +
			"its own here, which is worth pinning rather than assuming",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/realms/master/account/credentials/nosuchcredential",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "account/credentials/label-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: PUT /realms/{realm}/account/credentials/{id}/label",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "not served, and recorded beside the delete because the pair is what says " +
			"the 404 follows the credential rather than the route: `GET` on this same " +
			"path is the generic `HTTP 404 Not Found` and the `PUT` is `Credential " +
			"not found`, so the two 404s on one path are decided by the verb",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/realms/master/account/credentials/nosuchcredential/label",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
				"Content-Type":  "text/plain",
			},
			Body: []byte("office laptop"),
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --------------------------------------------------------------- sessions

	{
		ID: "account/sessions/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/sessions",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "Gloak's user sessions carry no ipAddress, no started, lastAccess or " +
			"expires stamps and no per-client breakdown, so the body has five fields " +
			"nothing in the store holds. It is a session-model cut rather than an " +
			"account-API one",
		// **Its own user**, because this listing counts logins and account-user
		// logs in once per case that names it. The first two recordings of this
		// golden differed in exactly that - eleven rows then twelve, with
		// `"current":true` at a different index - which is a golden that holds
		// only while the catalogue's order holds. The fixture is the fix; a
		// mask over the array would have hidden it.
		Fixture: "account-user-sessions",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/sessions",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Cache-Control", "Content-Type"},
		// The session is the fixture's own login and none of these five is
		// captured: the id is minted by the token endpoint, the three stamps are
		// seconds since the epoch, and the address is the recorder's container
		// bridge. Their presence and position stay asserted.
		Volatile: []string{
			"*/id", "*/ipAddress", "*/started", "*/lastAccess", "*/expires",
			"*/clients/*/clientId",
		},
	},
	{
		ID: "account/sessions/delete-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: DELETE /realms/{realm}/account/sessions/{id}",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "not served with the rest of the session family, and recorded because its " +
			"answer is a **204** for a session id that names nothing - where the " +
			"Admin API's DELETE .../sessions/{id} answers 404 `Sesssion not found`. " +
			"One concept, two APIs, opposite answers to the same missing row",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/realms/master/account/sessions/nosuchsession",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Cache-Control"},
		// A 204 whose request declared no application/* Content-Type, so
		// X-Frame-Options is absent - httpx.WriteNoContent's measured rule met
		// on a third API.
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},

	// ----------------------------------------------------------- applications

	{
		ID: "account/applications/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/applications",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "`inUse` is computed from the user's live client sessions and " +
			"`offlineAccess` from its offline ones, neither of which Gloak's session " +
			"store distinguishes; `userConsentRequired` and `clientName` come from " +
			"the client and are the easy half",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/applications",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		ID: "account/applications/consent-none",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/applications/{clientId}/consent",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "the consent family is not served. Its no-consent answer is recorded " +
			"because it is a **204 with no body** rather than a 200 with null or an " +
			"empty object, which is the answer a reader would write first",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/applications/account/consent",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/applications/consent-unknown-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/applications/{clientId}/consent",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "not served, and recorded because it is a **new spelling of not-found**: " +
			"`{\"errorMessage\":\"No client with clientId: x found.\"}` interpolates " +
			"the request's own value and carries a full stop, and it is on none of " +
			"the Admin API's thirty-six",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/applications/nosuchclient/consent",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "account/applications/consent-no-body-reader",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: POST /realms/{realm}/account/applications/{clientId}/consent",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "not served, and recorded because the 415 body is one this project has " +
			"not met: `{\"error\":\"No supported MessageBodyReader found\"}`. It fires " +
			"**before** the client is resolved - the same path's GET answers `No " +
			"client with clientId` for the same unknown client - so the body is " +
			"judged first here, which is client registration's order and not the " +
			"Admin API's",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/account/applications/nosuchclient/consent",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// ---------------------------------------------------------------- resources

	{
		ID: "account/resources/uma-disabled",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: GET /realms/{realm}/account/resources",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "user-managed access is off on every realm a default install has, so this " +
			"403 is the contract rather than a stub - the same situation as " +
			"client-types' 501 and organizations' realm flag. The six paths behind it " +
			"are unreachable without turning a realm's userManagedAccessAllowed on, " +
			"which nothing in Gloak models",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/resources",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "account/resources/gate-beats-method-dispatch",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: /realms/{realm}/account/resources",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "the same gate, and this is the request that says where it sits: PATCH is " +
			"405 on every other path on this API and **403** here, so the realm's UMA " +
			"flag is judged before the method is dispatched. It is counted in this " +
			"chapter rather than left to http/fallback for exactly that reason - it " +
			"is not a fallback cell",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodPatch,
			Path:   "/realms/master/account/resources",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// ---------------------------------------------------------------- dispatch

	{
		ID: "account/console/accept-html",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account console: GET /realms/{realm}/account with a browser Accept",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "the account console is a theme resource - 4222 bytes of markup, an " +
			"importmap of eleven vendored modules and a JSON environment block - and " +
			"the themes chapter is not enumerated. Gloak serves the REST branch for " +
			"every Accept, which is a declared divergence rather than an oversight: " +
			"answering the fallback 404 instead would be a second wrong answer and " +
			"would lose the JSON branch with it",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account",
			// No Accept header at all, which is the browser's own case and the
			// one that made the SAML sweep's discriminator useless here.
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/console/unknown-subpath",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account console: GET /realms/{realm}/account/{anything}",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "the same page, byte for byte, for a path no route serves - the console is " +
			"a client-side router and every deep link has to reach it. This is the " +
			"case that says the surface cannot be enumerated by sweeping 404s, and it " +
			"is separate from the one above because the two together are the " +
			"measurement: one path that exists and one that does not, one answer",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/nosuchsub",
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/dispatch/unknown-subpath-json",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: an unrouted path with Accept: application/json",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "Gloak has no route here, so its fallback answers the **unmatched-path** " +
			"body with none of the five security headers where Keycloak answers " +
			"`HTTP 404 Not Found` with all five - the account resource is reached " +
			"through a sub-resource locator, so the request is inside the filter " +
			"chain. It is F153's shape a third time and it is fixed by a wildcard " +
			"dispatcher under /account, which is a cut of its own",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/nosuchsub",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
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
		ID: "account/dispatch/accept-unparseable",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: an Accept header that is not a media type",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "`Accept: xyz` is a **500 unknown_error** - the negotiation parses the " +
			"header before anything else looks at it and a bare token is not a media " +
			"type. Gloak does not parse Accept at all here, so it answers the groups " +
			"read. Reproducing it means a media-type parser whose only consumer is " +
			"this one refusal",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "xyz",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "account/dispatch/options",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/#account-api",
			Section:   "Account REST API: OPTIONS on any account path",
			Retrieved: "2026-09-07",
		},
		Status: Recorded,
		Reason: "Gloak answers OPTIONS with the fallback 404 on every route it has, which " +
			"is F31 and is not this chapter's to change. It is counted here rather " +
			"than left to http/fallback because it is not a fallback cell: it is a " +
			"200 with an empty body, **no `Allow` header at all** and no " +
			"`Content-Type`, which is neither the SAML family's OPTIONS nor any 405",
		Fixture: "account-user",
		Request: Request{
			Method: http.MethodOptions,
			Path:   "/realms/master/account/groups",
			Headers: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer {{user_token}}",
			},
		},
		AssertHeaders: []string{
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Robots-Tag",
		},
		// Three negatives and each is a separate measurement. `Allow` is what
		// the SAML family sends and this one does not; `Content-Type` is absent
		// because the body is empty; `X-Frame-Options` is absent on an OPTIONS
		// 200, which AGENTS.md records as measured on four endpoints with no
		// golden holding it - this is the first golden that does.
		AssertAbsentHeaders: []string{"Allow", "Content-Type", "X-Frame-Options"},
	},
}

package oidc

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
)

// /realms/{realm}/protocol/saml and /realms/{realm}/protocol/saml/clients/{name}.
//
// Both are browser endpoints: every refusal either of them can produce is the
// login theme's error page with one sentence changed, and the sentence is the
// whole of what one refusal has that another does not.
//
// # The ladder, measured rung by rung on 2026-09-11
//
// The first cut of this chapter measured **five** rungs and served none of them,
// because the fifth is a 200 and a handler answering the first four without
// walking to it is right on every case in a catalogue and wrong on the only
// request a SAML client ever sends. This cut re-measured the ladder one input at
// a time and it is **seven** rungs, not five:
//
//	the message will not decode or parse         Invalid Request
//	its Issuer names no client in the realm      Invalid Request
//	the client is disabled                       Login requester not enabled
//	the client is bearer-only                    Bearer-only applications are not
//	                                             allowed to initiate browser login
//	the client's protocol is not saml            Wrong client protocol.
//	the signature is required and does not verify   Invalid requester
//	the Destination is wrong, or absent on a
//	  signed message                             Invalid Request
//	no assertion consumer URL resolves           Invalid redirect uri
//	                                             -> the login page
//
// **Two of those rungs are new and both invert something the first cut wrote
// down.** `Login requester not enabled` runs **before** the protocol check - a
// disabled `openid-connect` client answers it rather than
// `Wrong client protocol.` - and so does the bearer-only refusal, measured on a
// bearer-only `openid-connect` client and on a bearer-only SAML client that also
// requires a signature. So a ladder written as "client, protocol, signature"
// puts two checks on the wrong side of the protocol one.
//
// # The chrome names the client only from the signature rung up
//
// Measured on every rung: the restart URL in the page's head carries
// `client_id=<id>` on `Invalid requester` and `Invalid redirect uri` and carries
// **nothing** on `Invalid Request`, `Login requester not enabled`,
// `Bearer-only…` and `Wrong client protocol.` - although the last three have
// resolved a client by then. That is the rule internal/oidc/themepage.go already
// records from the `/auth` side, met here on four more sentences.
//
// # What this file does not serve, and why the answer is a 404
//
// A request that passes every rung is answered by Keycloak with a login page
// (HTTP-Redirect binding) or a 302 into the authentication flow (HTTP-POST
// binding), and the flow ends in a **signed SAML assertion** posted back to the
// service provider. Gloak has no assertion builder and no SAML session, so
// there is nothing true to answer. The request therefore falls through to
// protocolDispatch's `HTTP 404 Not Found`, which is what this whole endpoint
// answered before this cut: the divergence is confined to the one behaviour
// that is not built, rather than being spread over the ladder by answering
// `Invalid requester` to a client whose signature is good.
//
// A `LogoutRequest` that passes every rung is the same situation and is answered
// the same way. Keycloak's own answer to it is a 500 - two of them, one per
// binding - and they are `Recorded` rather than served, because that 500 is
// Keycloak failing to log out a session that does not exist and a handler
// sending it unconditionally would answer 500 to a logout that ought to succeed.
// See saml/endpoint/logout-request-redirect and its POST sibling.

// samlEndpoint serves GET and POST on /realms/{realm}/protocol/saml.
//
// The two verbs are one handler, which is measured: a POST carrying an empty
// form answers the identical page a GET with no parameters does. They differ in
// exactly two things - the message's encoding, and the response's
// `Cache-Control` - and both are handled where they arise rather than by two
// handlers that would drift.
func (h *handler) samlEndpoint(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	message, encoded, ok := h.readSAMLRequest(r)
	if !ok {
		h.writeSAMLPage(w, r, h.themeChrome(realm), pageInvalidRequest)
		return
	}
	client, err := h.store.Clients().ByClientID(r.Context(), realm.ID, message.Issuer)
	if err != nil {
		// An Issuer naming no client and a store failure are one page here,
		// for resolveAuthClient's reason: nothing observable tells them apart.
		h.writeSAMLPage(w, r, h.themeChrome(realm), pageInvalidRequest)
		return
	}
	if instruction, refused := samlClientRefusal(client); refused {
		h.writeSAMLPage(w, r, h.themeChrome(realm), instruction)
		return
	}
	if clientRequiresSignature(client) && !h.verifySAMLSignature(r, client) {
		h.writeSAMLPage(w, r, h.themeChromeFor(realm, client), pageInvalidRequester)
		return
	}
	if !h.samlDestinationAccepted(r, realm, message, encoded) {
		h.writeSAMLPage(w, r, h.themeChromeFor(realm, client), pageInvalidRequest)
		return
	}
	acs := samlAssertionConsumerURL(client, message)
	if message.Kind == samlAuthnRequest && acs == "" {
		h.writeSAMLPage(w, r, h.themeChromeFor(realm, client), pageInvalidLogoutRedirect)
		return
	}
	if message.Kind != samlAuthnRequest {
		// A LogoutRequest that passes every rung is Keycloak failing to end a
		// session that does not exist, which is a 500 that must not be sent
		// unconditionally. See the block comment and
		// saml/endpoint/logout-request-redirect.
		httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
		return
	}
	h.beginSAMLLogin(w, r, realm, client, samlLogin{
		ACSURL:      acs,
		RequestID:   message.ID,
		Binding:     samlResponseBinding(client, message.ProtocolBinding),
		RelayState:  samlRelayState(r),
		BareHeaders: true,
	})
}

// samlLogin is what the eighth rung of either route has to know, gathered into
// one value because the two routes fill it differently in every field and a
// six-argument call would put the differences where nobody reads them.
type samlLogin struct {
	// ACSURL is the resolved assertion consumer URL, which is client_data's
	// `ru` and is the tab's RedirectURI.
	ACSURL string
	// RequestID is the AuthnRequest's ID, and it is **empty on the
	// IdP-initiated route**, where client_data is measured to carry no `rt` at
	// all rather than an empty one.
	RequestID string
	// Binding is client_data's `rm`; see samlResponseBinding.
	Binding string
	// RelayState becomes `st`, and an empty one is measured **absent** where
	// /auth's `state=` is present and empty.
	RelayState string
	// BareHeaders says the answer carries none of the five security headers and
	// no Content-Security-Policy, which is measured true of
	// `/realms/{realm}/protocol/saml` and false of
	// `/realms/{realm}/protocol/saml/clients/{name}` one segment down. The two
	// routes' 400 pages already split the same way.
	BareHeaders bool
}

// beginSAMLLogin is the eighth rung: a request that passed every check opens an
// authentication session and is asked for credentials.
//
// # The two bindings answer differently and neither is the other's shape
//
// Measured 2026-09-18 on one container, the same client and the same message
// over each:
//
//	GET  /protocol/saml   200, the login page, three Set-Cookie,
//	                      Cache-Control: no-store, must-revalidate, max-age=0,
//	                      **none** of the five security headers and no CSP
//	POST /protocol/saml   302 into /login-actions/authenticate, empty body,
//	                      three Set-Cookie, Cache-Control: no-cache,
//	                      none of the six, and **no Content-Type at all**
//
// So the verb split this endpoint already has on Cache-Control reaches the
// whole response: one binding renders the page and the other sends the browser
// to the endpoint that will.
//
// # What the session carries, and why every field of it is observable
//
// The tab's four SAML facts all come back out in client_data, which the login
// page carries twice - in the head's restart URL and in the form's action - and
// which the 302 carries in its Location. Measured shapes are on
// authTab.SAMLBinding and on clientData.
//
// # The browser's second request is the ordinary flow's
//
// Both answers hand the browser to `/login-actions/authenticate`, which is the
// same endpoint an OIDC login goes through, so nothing below this is SAML's.
// What *is* SAML's is the ending, and there is not one: finishFlow declines a
// SAML tab rather than minting an authorization code for it, because a code is
// what an OIDC client asked for and this client asked for an assertion. See
// F227's remainder and completeSAMLLogin.
func (h *handler) beginSAMLLogin(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, login samlLogin) {
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}
	tab := &authTab{
		ClientID:      client.ClientID,
		ClientUUID:    client.ID,
		RedirectURI:   login.ACSURL,
		State:         login.RelayState,
		HasState:      login.RelayState != "",
		SAMLBinding:   login.Binding,
		SAMLRequestID: login.RequestID,
	}
	sess, err := h.beginAuthSession(w, r, realm, k, tab, &restartRecord{
		Realm:         realm.Name,
		ClientID:      client.ClientID,
		RedirectURI:   login.ACSURL,
		State:         login.RelayState,
		HasState:      login.RelayState != "",
		SAMLBinding:   login.Binding,
		SAMLRequestID: login.RequestID,
	})
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if r.Method == http.MethodPost {
		data, err := tab.clientData()
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		// The measured key order is client_id, tab_id, client_data, and there
		// is no session_code: the landing request is what mints one. It is the
		// restart landing's order exactly, one endpoint along.
		httpx.WriteSAMLLoginRedirect(w, h.realmBase(realm.Name)+
			"/login-actions/authenticate?"+strings.Join([]string{
			"client_id=" + url.QueryEscape(client.ClientID),
			"tab_id=" + url.QueryEscape(tab.TabID),
			"client_data=" + url.QueryEscape(data),
		}, "&"))
		return
	}
	if login.BareHeaders {
		h.serveSAMLLoginPage(r.Context(), w, realm, client, sess, tab)
		return
	}
	h.serveLoginPage(r.Context(), w, realm, client, sess, tab, "", "")
}

// samlRelayState reads the RelayState off whichever binding carried it: the
// query on HTTP-Redirect, the form on HTTP-POST.
//
// **It is not r.FormValue, and the difference is one input wide.** ParseForm
// fills r.Form with the body's values first and appends the query's, so
// FormValue and PostFormValue return the same thing on every request whose body
// carries the parameter. They differ on exactly one: a POST whose **body omits
// RelayState and whose query carries one**.
//
// Measured 2026-09-18 on a fresh container, that input renders **no `st` key at
// all** - the POST binding reads its RelayState from the body alone and ignores
// the query, so PostFormValue is right and a merged read is wrong there and
// nowhere else. readSAMLRequest takes the same care with SAMLRequest, and that
// is measured too: a POST carrying its message in the query answers
// `Invalid Request` at the ladder's floor in both encodings.
//
// The pair is worth stating because a test sending both spellings with
// different values cannot tell the two readers apart - it is the input that
// looks discriminating and is not. See
// TestSAMLPostBindingReadsItsRelayStateFromTheForm's third subtest.
func samlRelayState(r *http.Request) string {
	if r.Method == http.MethodPost {
		return r.PostFormValue("RelayState")
	}
	return r.URL.Query().Get("RelayState")
}

// samlResponseBinding is client_data's `rm`, and its grid is measured rather
// than derived from the request.
//
//	saml.force.post.binding == "true"          post, whatever the request says
//	otherwise, ProtocolBinding is HTTP-POST    post
//	otherwise                                  get
//
// **HTTP-Artifact is `get`**, which is the cell a reader gets wrong: the
// descriptor advertises an artifact binding, the attribute names it, and the
// answer is the default rather than a third value or a refusal. HTTP-Redirect
// and an absent attribute are `get` too, so only one of the four spellings
// moves the answer.
//
// The attribute is compared to the exact string "true", case-sensitively -
// measured across "true", "TRUE", "True", " true", "false", "", "0" and "no",
// and only the first is on. That is clientRequiresSignature's rule met on a
// second attribute, so the comparison is shared rather than written twice.
func samlResponseBinding(client *model.Client, protocolBinding string) string {
	if samlAttributeIsTrue(client, "saml.force.post.binding") ||
		protocolBinding == samlHTTPPOSTBinding {
		return samlBindingPost
	}
	return samlBindingGet
}

// The two values client_data's `rm` is measured to carry on a SAML tab, and the
// one ProtocolBinding spelling that decides between them.
const (
	samlBindingPost     = "post"
	samlBindingGet      = "get"
	samlHTTPPOSTBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// samlIdPInitiated serves GET /realms/{realm}/protocol/saml/clients/{name}.
//
// # The segment is an attribute, not a clientId
//
// It is `saml_idp_initiated_sso_url_name`. Measured on one container: one client
// answers `Client not found.` for its own clientId and `Invalid redirect uri`
// for the value of that attribute, and `GET .../clients/account` - a
// bootstrapped clientId every install has - answers `Client not found.` too. A
// handler looking clients up by clientId answers a name nothing carries
// correctly **by accident**, so the two cases a reader writes first cannot see
// the bug.
//
// # Its ladder is three rungs and the order is not the endpoint's
//
//	no client carries the name       Client not found.
//	the client is disabled           Client disabled.
//	its protocol is not saml         Wrong client protocol.
//	no assertion consumer URL        Invalid redirect uri
//	                                 -> the login page
//
// **The name is looked up across protocols**: an `openid-connect` client
// carrying the attribute answers `Wrong client protocol.` rather than
// `Client not found.`, so the lookup does not filter by protocol and the check
// is a rung of its own. And the disabled check runs before it - a **disabled**
// `openid-connect` client carrying the attribute answers `Client disabled.`
//
// # One client, two routes, two sentences for one state
//
// A disabled SAML client is `Client disabled.` here and
// `Login requester not enabled` on /protocol/saml, measured on the same client
// on one container. The two routes also disagree about headers: this one sends
// all five security headers and a Content-Security-Policy where /protocol/saml
// one segment up sends none of them.
func (h *handler) samlIdPInitiated(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	client := h.clientByIdPInitiatedName(r, realm, r.PathValue("name"))
	if client == nil {
		h.writeIdPInitiatedPage(w, h.themeChrome(realm), pageClientNotFound)
		return
	}
	if !client.Enabled {
		h.writeIdPInitiatedPage(w, h.themeChrome(realm), pageClientDisabled)
		return
	}
	if client.Protocol != protocolSAML {
		h.writeIdPInitiatedPage(w, h.themeChrome(realm), pageWrongClientProtocol)
		return
	}
	acs := samlAssertionConsumerURL(client, nil)
	if acs == "" {
		h.writeIdPInitiatedPage(w, h.themeChromeFor(realm, client), pageInvalidLogoutRedirect)
		return
	}
	// **The fourth rung is the login page with the ordinary header set**, which
	// is the one place these two routes agree with the rest of the server and
	// disagree with each other. Measured 2026-09-18: 200, all five security
	// headers and a Content-Security-Policy, where /protocol/saml's own login
	// page one segment up sends none of the six.
	//
	// Its client_data is a **third** shape: `{"ru":<ACS>,"rm":"post"}`, with no
	// `rt` at all, because there is no request and therefore no request id. A
	// RelayState may still be sent, as a query parameter, and it becomes `st`
	// under the same empty-is-absent rule the endpoint has.
	h.beginSAMLLogin(w, r, realm, client, samlLogin{
		ACSURL:     acs,
		Binding:    samlResponseBinding(client, ""),
		RelayState: samlRelayState(r),
	})
}

// clientByIdPInitiatedName finds the client claiming an IdP-initiated SSO name.
//
// It scans the realm because the name is a client **attribute** and no index
// exists for one. A realm's client list is small - a default install has six -
// and the alternative is a store method for one route.
func (h *handler) clientByIdPInitiatedName(r *http.Request, realm *model.Realm,
	name string) *model.Client {
	if name == "" {
		return nil
	}
	clients, err := h.store.Clients().ListByRealm(r.Context(), realm.ID)
	if err != nil {
		return nil
	}
	for _, client := range clients {
		if client.Attributes["saml_idp_initiated_sso_url_name"] == name {
			return client
		}
	}
	return nil
}

// readSAMLRequest decodes and parses the request's SAML message, and reports
// the message's own encoded parameter beside it.
//
// **`SAMLRequest` wins over `SAMLResponse`**, measured: a lone `SAMLResponse`
// carrying a perfectly good AuthnRequest is `Invalid Request`, and a request
// carrying both parameters is served from the `SAMLRequest`.
//
// **Each binding reads exactly one source, and that is measured rather than
// assumed.** The POST branch is PostFormValue and not FormValue: a POST
// carrying its `SAMLRequest` in the **query** answers `Invalid Request` at
// 3572 bytes - the ladder's floor, the page a request with no parameters at all
// gets - in both the POST encoding and the redirect one. So the query is not
// one of this binding's sources, and a merged read would serve a login page to
// a request Keycloak refuses. Measured 2026-09-18; see
// TestSAMLPostBindingReadsItsMessageFromTheFormToo and samlRelayState, which is
// the same rule on the parameter beside it.
func (h *handler) readSAMLRequest(r *http.Request) (*samlMessage, string, bool) {
	var encoded string
	var doc []byte
	var decoded bool
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, "", false
		}
		encoded = r.PostFormValue("SAMLRequest")
		doc, decoded = decodeSAMLPost(encoded)
	} else {
		encoded = r.URL.Query().Get("SAMLRequest")
		doc, decoded = decodeSAMLRedirect(encoded)
	}
	if encoded == "" || !decoded {
		return nil, "", false
	}
	message, ok := parseSAMLMessage(doc)
	if !ok {
		return nil, "", false
	}
	return message, encoded, true
}

// samlClientRefusal is the three checks that run between resolving a client and
// looking at the signature, in the measured order.
//
// The order is the finding. `Login requester not enabled` and the bearer-only
// sentence both come **before** the protocol check, measured on a disabled
// `openid-connect` client and on a bearer-only one: both answer their own
// sentence rather than `Wrong client protocol.`, although their protocol is the
// wrong one and that is the check a reader would expect first.
func samlClientRefusal(client *model.Client) (string, bool) {
	switch {
	case !client.Enabled:
		return pageLoginRequesterNotEnabled, true
	case client.BearerOnly:
		return pageBearerOnly, true
	case client.Protocol != protocolSAML:
		return pageWrongClientProtocol, true
	}
	return "", false
}

// verifySAMLSignature checks the message's signature, for the one binding whose
// signature this project can check.
//
// The HTTP-POST binding's is an enveloped XML signature over a canonicalised
// document and nothing in the standard library canonicalises XML, so a POST
// message from a client requiring a signature is reported **unverified** here
// and samlEndpoint answers it the way it answers everything else it cannot
// serve. Reporting it refused instead would answer `Invalid requester` to a
// correctly signed POST, which is the error this whole ladder exists to avoid.
// See F229.
func (h *handler) verifySAMLSignature(r *http.Request, client *model.Client) bool {
	if r.Method == http.MethodPost {
		return false
	}
	return verifyRedirectSignature(client, r.URL.RawQuery)
}

// samlDestinationAccepted is the Destination rung, and its predicate is not the
// one it looks like.
//
// Measured 2026-09-11, four cells on one container:
//
//	unsigned, no Destination attribute      accepted - reaches the login page
//	unsigned, Destination=""                accepted
//	unsigned, Destination naming another port  Invalid Request
//	**signed**, no Destination attribute     Invalid Request
//	signed, Destination=""                   Invalid Request
//	signed, Destination exact                accepted
//
// So a Destination is **optional until the request carries a `Signature`
// parameter**, and it is the parameter that decides rather than the client's
// `saml.client.signature` flag: a client with the flag **off**, sent a junk
// signature and no Destination, answers `Invalid Request` and not
// `Invalid requester` - the signature is not even looked at and the Destination
// is required anyway.
//
// **That single cell is what makes this whole endpoint reachable from a
// catalogue.** The first cut concluded a literal AuthnRequest could never work
// on the recorder's mapped port, and opened F175 for a fixture field to mint
// one. Omitting the Destination removes the port from the message.
//
// When a Destination is compared it is compared **exactly**: a trailing slash,
// `https` for `http`, `127.0.0.1` for `localhost`, the port left off, a query
// appended, another realm and another path are all refused.
func (h *handler) samlDestinationAccepted(r *http.Request, realm *model.Realm,
	message *samlMessage, encoded string) bool {
	_ = encoded
	signed := r.Method != http.MethodPost && r.URL.Query().Get("Signature") != ""
	if message.Destination == "" {
		return !signed
	}
	return message.Destination == h.issuerBase+"/realms/"+realm.Name+"/protocol/saml"
}

// samlAssertionConsumerURL resolves where an assertion would be posted, and
// returns "" when nothing resolves - which is the `Invalid redirect uri` rung.
//
// The rule has two halves and they do not use the same source, measured
// 2026-09-11:
//
//   - **the message names one**: it is accepted only if it matches the client's
//     registered **redirectUris**, by the same predicate an OIDC redirect_uri
//     goes through. All seven of matchRedirectURI's sharp cells were re-measured
//     here and agree - an exact pattern refuses an appended query and an appended
//     slash, a wildcard cuts the query, `http://localhost:99990/evil` is refused
//     against `http://localhost:9999/*`, a pattern containing `?` is never a
//     wildcard, and a `*` that is not last matches nothing.
//   - **the message names none**: the client's own
//     `saml_assertion_consumer_url_post` or `saml_assertion_consumer_url_redirect`
//     attribute answers, and **it is not checked against redirectUris at all** -
//     a client with an empty `redirectUris` and the attribute set reaches the
//     login page.
//
// The two halves crossing is the cell a reader would get wrong: a client whose
// only ACS is the attribute, sent a message naming that same URL, is
// **refused**, because the message named one and the redirectUris did not match
// it. Measured directly.
//
// message is nil on the IdP-initiated route, where there is no message and the
// attribute is the only source.
func samlAssertionConsumerURL(client *model.Client, message *samlMessage) string {
	if message != nil && message.ACSURL != "" {
		if matchRedirectURI(client.RedirectURIs, message.ACSURL) {
			return message.ACSURL
		}
		return ""
	}
	for _, attribute := range []string{
		"saml_assertion_consumer_url_post",
		"saml_assertion_consumer_url_redirect",
	} {
		if url := client.Attributes[attribute]; url != "" {
			return url
		}
	}
	return ""
}

// writeSAMLPage writes /protocol/saml's error page.
//
// **It sends none of the five security headers and no Content-Security-Policy**,
// which is measured and is the sharpest instance of the rule AGENTS.md records
// as having been wrong six times: this page and `/protocol/openid-connect/auth`'s
// are byte-identical and their header sets are complementary. One path segment
// down, writeIdPInitiatedPage sends all six.
//
// The `Cache-Control` is decided by the **verb**, measured on both of them:
// a GET answers `no-store, must-revalidate, max-age=0` and a POST answers
// `no-cache`, on the same path with the same body. The two committed goldens
// saml/endpoint/redirect-binding-saml-client and its `post-binding-` sibling
// show it without a container.
func (h *handler) writeSAMLPage(w http.ResponseWriter, r *http.Request,
	c httpx.ThemeChrome, instruction string) {
	httpx.WriteThemeErrorPageBare(w, http.StatusBadRequest, samlPageCacheControl(r), c, instruction)
}

// writeIdPInitiatedPage writes /protocol/saml/clients/{name}'s error page, which
// is the same template with the ordinary header set: all five security headers
// and a Content-Security-Policy, and `no-store, must-revalidate, max-age=0`.
func (h *handler) writeIdPInitiatedPage(w http.ResponseWriter, c httpx.ThemeChrome,
	instruction string) {
	httpx.WriteThemeErrorPage(w, http.StatusBadRequest, samlPageCacheStore, c, instruction)
}

// samlPageCacheControl is the verb split described on writeSAMLPage.
func samlPageCacheControl(r *http.Request) string {
	if r.Method == http.MethodPost {
		return "no-cache"
	}
	return samlPageCacheStore
}

const samlPageCacheStore = "no-store, must-revalidate, max-age=0"

// protocolSAML is the value model.Client.Protocol carries for a SAML client.
// It is compared exactly, the way Keycloak's protocol map is: `SAML` is not it.
const protocolSAML = "saml"

// The three sentences this family adds to internal/oidc/themepage.go's list,
// all measured on 2026-09-11.
//
// pageLoginRequesterNotEnabled has **no full stop** where pageClientDisabled,
// its opposite number one path segment away for the same client in the same
// state, has one. Two routes, one condition, two spellings - which is the shape
// AGENTS.md's not-found list records twenty-eight times on the Admin API, met
// here on a browser page.
//
// pageWrongClientProtocol is shared by both routes and does have a full stop.
//
// pageInvalidRequester has none. It is the **signature** refusal and not a
// statement that the client is unknown, which is the measurement the first cut
// of this chapter was built around.
const (
	pageLoginRequesterNotEnabled = "Login requester not enabled"
	pageWrongClientProtocol      = "Wrong client protocol."
	pageInvalidRequester         = "Invalid requester"
)

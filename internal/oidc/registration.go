package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/token"
)

// Dynamic client registration, the `openid-connect` provider of
// /realms/{realm}/clients-registrations/{provider}.
//
// Measured 2026-08-31 against a live 26.7.1. Three of the endpoint's answers
// are not what its documentation suggests:
//
//   - **An ordinary administrator's access token registers a client.** No
//     initial access token is needed, and the two produce a registration access
//     token carrying the same `registration_auth`. That is what lets the
//     conformance fixtures reach this endpoint at all: minting an initial
//     access token is POST /admin/realms/{r}/clients-initial-access, which
//     Gloak does not serve.
//   - **The body is decoded before the caller is judged**, on POST and PUT
//     alike. A request with no Content-Type and no credentials answers 415, and
//     one with malformed JSON and no credentials answers 400 - not the refusal
//     an anonymous caller gets for a well-formed request.
//   - **The two 403s have different bodies.** A caller presenting no bearer
//     token at all is told about the "Trusted Hosts" client registration
//     policy; one presenting a valid access token without the role is told
//     `Forbidden`. One "not allowed" constant is wrong on one of them.
const registrationProvider = "openid-connect"

// The refusals, in the measured order. Each adjacency was driven by a request
// wrong in two ways at once, which is what fixes the order rather than the list.
//
//  1. the realm                     404  {"error":"Realm does not exist"}
//  2. the request's Content-Type    415  the bare-error 415 below
//  3. the body parses               400  invalid_request / Cannot parse the JSON
//  4. the bearer verifies           401  invalid_token / Failed decode token
//  5. the bearer's type             401  invalid_token / Invalid type of token
//  6. no credential at all          403 on the create, 401 on an item - and the
//     item's sentence splits by verb
//  7. the caller's role             403  insufficient_scope / Forbidden
//  8. the client                    404  invalid_request / Client not found
const (
	descTrustedHosts = "Policy 'Trusted Hosts' rejected request to client-registration service. " +
		"Details: Host not trusted."
	descForbidden = "Forbidden"
	// descFailedDecode is what a bearer that does not verify gets, and the word
	// is measured to be wider than it reads: a **well-formed JWT with a wrong
	// signature** answers it too, not only unparseable input.
	descFailedDecode = "Failed decode token"
	// descInvalidTokenType is a token that verifies and is the wrong kind - a
	// refresh token offered as a bearer.
	descInvalidTokenType = "Invalid type of token"
	// The two "not authorized" sentences differ by **verb**, both 401
	// invalid_token: a GET is told about viewing and a PUT or DELETE about
	// updating, and their second halves differ as well.
	descNotAuthorizedView   = "Not authorized to view client. Not valid token or client credentials provided."
	descNotAuthorizedUpdate = "Not authorized to update client. Maybe missing token or bad token type."
	descClientNotFound      = "Client not found"
	descCannotParseJSON     = "Cannot parse the JSON"
	// descUnsupportedMediaType is the bare-error shape - one key, prose, no
	// OAuth code - and names a JAX-RS annotation in a response a client sees.
	descUnsupportedMediaType = "The content-type header value did not match the value in @Consumes"
	// descClientIdentifierIncluded is a create naming a client_id;
	// descClientIdentifierModified is an update whose body's client_id does not
	// equal the path's, **including when the body names none at all**. One
	// message for two conditions on the update.
	descClientIdentifierIncluded = "Client Identifier included"
	descClientIdentifierModified = "Client Identifier modified"
	// descClientMetadataInvalid is the catch-all for a value the converter
	// cannot map, measured on token_endpoint_auth_method.
	descClientMetadataInvalid = "Client metadata invalid"
)

const (
	errInsufficientScope = "insufficient_scope"
	errInvalidToken      = "invalid_token"
	errInvalidClientMeta = "invalid_client_metadata"
)

// The three admin role names this endpoint reads, measured one caller at a
// time: `create-client` or `manage-clients` open the create, `view-clients` or
// `manage-clients` open a read, and `manage-clients` alone opens an update or a
// delete. `query-clients` and `manage-realm` open nothing here.
const (
	registrationRoleCreate = "create-client"
	registrationRoleManage = "manage-clients"
	registrationRoleView   = "view-clients"
)

// The token_endpoint_auth_method values the create accepts, and the
// clientAuthenticatorType each maps to. Measured on all nine spellings RFC 7591
// and the discovery document between them suggest:
//
//	client_secret_basic          client-secret, confidential
//	client_secret_post           client-secret, confidential, plus the
//	                             client.secret.authentication.allowed.method attribute
//	client_secret_jwt            client-secret-jwt, confidential
//	tls_client_auth              client-x509, confidential
//	none                         none, public
//	private_key_jwt              **refused**
//	self_signed_tls_client_auth  refused
//	an unknown value             refused
//	the empty string             refused
//
// **`private_key_jwt` is refused on the way in and produced on the way out.**
// The discovery document advertises it in token_endpoint_auth_methods_supported
// and a client created through the Admin API with clientAuthenticatorType
// `client-jwt` reads back as exactly that here, so the set this endpoint accepts
// and the set it emits are different sets. One constant for "the auth methods"
// is wrong on one of them.
const (
	authMethodSecretBasic = "client_secret_basic"
	authMethodSecretPost  = "client_secret_post"
	authMethodSecretJWT   = "client_secret_jwt"
	authMethodTLS         = "tls_client_auth"
	authMethodPrivateJWT  = "private_key_jwt"
	authMethodNone        = "none"

	authenticatorSecret    = "client-secret"
	authenticatorSecretJWT = "client-secret-jwt"
	authenticatorX509      = "client-x509"
	authenticatorJWT       = "client-jwt"
	authenticatorNone      = "none"
)

// Client attributes this endpoint reads and writes.
//
// attrSecretMethod records which of the two secret-carrying spellings the
// caller asked for, and is written **only** when the create named the field: a
// default create carries no such attribute and still reads back
// client_secret_basic. attrUseRefreshTokens is written by any create that names
// grant_types at all, empty array included, and decides whether the read emits
// refresh_token.
const (
	attrSecretMethod     = "client.secret.authentication.allowed.method"
	attrUseRefreshTokens = "use.refresh.tokens"
	attrSecretCreated    = "client.secret.creation.time"
	attrRealmClient      = "realm_client"
	attrPostLogoutURIs   = "post.logout.redirect.uris"
	attrDPoPBound        = "dpop.bound.access.tokens"
	attrTLSBound         = "tls.client.certificate.bound.access.tokens"
	attrRequirePAR       = "require.pushed.authorization.requests"
	attrBackchannelSess  = "backchannel.logout.session.required"
	attrBackchannelRevo  = "backchannel.logout.revoke.offline.tokens"
	attrFrontchannelSess = "frontchannel.logout.session.required"
	attrDeviceGrant      = "oauth2.device.authorization.grant.enabled"
	attrCIBAGrant        = "oidc.ciba.grant.enabled"
	attrExchangeGrant    = "standard.token.exchange.enabled"
	attrJWTBearerGrant   = "oauth2.jwt.authorization.grant.enabled"
)

// The four grant type strings that have a flow flag of their own.
const (
	grantTypeAuthorizationCode = "authorization_code"
	grantTypeImplicit          = "implicit"
	grantTypePassword          = "password"
	grantTypeClientCredentials = "client_credentials"
)

// oidcClientRepresentation is the body this endpoint speaks, in the measured
// key order.
//
// Four shapes come out of one struct and the omitempty tags are what pick
// between them, every one of them measured:
//
//   - `client_name` is dropped when the client has none, where every array is
//     emitted empty.
//   - `client_secret` and `client_secret_expires_at` are governed by different
//     things. The expiry appears whenever the client's authenticator is one of
//     the secret-carrying ones; the secret itself only when the client is also
//     confidential. `admin-cli` - public, authenticator client-secret - carries
//     the expiry and not the secret, and a client registered with
//     `token_endpoint_auth_method: "none"` carries neither.
//   - `client_id_issued_at` is emitted by the **create** and by neither read.
//   - `registration_access_token` is emitted by the create, by the update, and
//     by a read made with a registration access token - and **not** by a read
//     made with an administrator's. So the administrator's read is a fourth
//     shape, and a shared serialiser is wrong on three of the four.
type oidcClientRepresentation struct {
	RedirectURIs                          []string `json:"redirect_uris"`
	TokenEndpointAuthMethod               string   `json:"token_endpoint_auth_method"`
	GrantTypes                            []string `json:"grant_types"`
	ResponseTypes                         []string `json:"response_types"`
	ClientID                              string   `json:"client_id"`
	ClientSecret                          string   `json:"client_secret,omitempty"`
	ClientName                            string   `json:"client_name,omitempty"`
	ClientURI                             string   `json:"client_uri,omitempty"`
	Scope                                 string   `json:"scope"`
	SubjectType                           string   `json:"subject_type"`
	RequestURIs                           []string `json:"request_uris"`
	TLSClientCertificateBoundAccessTokens bool     `json:"tls_client_certificate_bound_access_tokens"`
	DPoPBoundAccessTokens                 bool     `json:"dpop_bound_access_tokens"`
	PostLogoutRedirectURIs                []string `json:"post_logout_redirect_uris"`
	ClientIDIssuedAt                      *int64   `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt                 *int     `json:"client_secret_expires_at,omitempty"`
	RegistrationClientURI                 string   `json:"registration_client_uri"`
	RegistrationAccessToken               string   `json:"registration_access_token,omitempty"`
	BackchannelLogoutSessionRequired      bool     `json:"backchannel_logout_session_required"`
	RequirePushedAuthorizationRequests    bool     `json:"require_pushed_authorization_requests"`
	FrontchannelLogoutSessionRequired     bool     `json:"frontchannel_logout_session_required"`
}

// registrationRequest is what the endpoint accepts.
//
// The pointers are presence, not value. `grant_types: []` and an absent
// `grant_types` produce different clients - the empty array turns
// use.refresh.tokens off and leaves the flow flags alone - so a plain slice,
// whose nil and empty forms are indistinguishable after a decode, cannot say
// which arrived.
type registrationRequest struct {
	ClientID                *string   `json:"client_id"`
	ClientName              *string   `json:"client_name"`
	ClientURI               *string   `json:"client_uri"`
	RedirectURIs            *[]string `json:"redirect_uris"`
	PostLogoutRedirectURIs  *[]string `json:"post_logout_redirect_uris"`
	GrantTypes              *[]string `json:"grant_types"`
	ResponseTypes           *[]string `json:"response_types"`
	TokenEndpointAuthMethod *string   `json:"token_endpoint_auth_method"`
	SubjectType             *string   `json:"subject_type"`
	DPoPBoundAccessTokens   *bool     `json:"dpop_bound_access_tokens"`

	TLSClientCertificateBoundAccessTokens *bool `json:"tls_client_certificate_bound_access_tokens"`
	RequirePushedAuthorizationRequests    *bool `json:"require_pushed_authorization_requests"`
	BackchannelLogoutSessionRequired      *bool `json:"backchannel_logout_session_required"`
	FrontchannelLogoutSessionRequired     *bool `json:"frontchannel_logout_session_required"`
}

// registerClient serves POST /realms/{realm}/clients-registrations/openid-connect.
func (h *handler) registerClient(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	rep, ok := decodeRegistration(w, r)
	if !ok {
		return
	}
	caller, ok := h.registrationCaller(w, r, realm, nil)
	if !ok {
		return
	}
	if !caller.mayCreate() {
		writeRegistrationRefusal(w, caller, false)
		return
	}
	// The client_id is the server's to mint. A body naming one is refused, and
	// that is why nothing this endpoint creates has a readable name: every
	// registered client's clientId is a UUID.
	if rep.ClientID != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest,
			errInvalidClientMeta, descClientIdentifierIncluded)
		return
	}
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}

	id := model.NewID()
	client := &model.Client{
		ID:                        id,
		RealmID:                   realm.ID,
		ClientID:                  id,
		Enabled:                   true,
		Protocol:                  "openid-connect",
		FullScopeAllowed:          true,
		NodeReRegistrationTimeout: -1,
		Attributes:                map[string]string{},
	}
	if !applyRegistration(w, client, rep) {
		return
	}
	if err := bootstrap.InheritClientScopes(r.Context(), h.store, realm.ID, client); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.store.Clients().Create(r.Context(), client); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	rat, err := h.mintRegistrationToken(realm, client, k)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	issuedAt := time.Now().Unix()
	body := h.registrationBody(realm, client, rat)
	body.ClientIDIssuedAt = &issuedAt
	w.Header().Set("Location", h.registrationURI(realm.Name, client.ClientID))
	// No Cache-Control: measured absent on every response this family sends,
	// success and refusal alike, where the token endpoint one path away sends
	// no-store on all of its.
	httpx.WriteJSONCharset(w, http.StatusCreated, body)
}

// readRegisteredClient serves GET on the item path.
func (h *handler) readRegisteredClient(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	client, caller, ok := h.authorizeRegistered(w, r, realm, false)
	if !ok {
		return
	}
	// The registration access token is echoed back to its holder and withheld
	// from an administrator reading the same client. Two bodies, one route,
	// decided by which credential asked.
	var rat string
	if caller.holder {
		rat = caller.presented
	}
	httpx.WriteJSONCharset(w, http.StatusOK, h.registrationBody(realm, client, rat))
}

// updateRegisteredClient serves PUT on the item path.
//
// It **rotates** the registration access token: the one the caller presented is
// refused immediately afterwards, measured. A GET does not - two reads with one
// token answered with that same token both times and it went on working.
func (h *handler) updateRegisteredClient(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	// The body is decoded before the caller is looked at, the same as the
	// create: a PUT carrying `{` and no credentials answers about the JSON.
	rep, ok := decodeRegistration(w, r)
	if !ok {
		return
	}
	client, _, ok := h.authorizeRegistered(w, r, realm, true)
	if !ok {
		return
	}
	// The body's client_id must equal the path's, and an **absent** one is the
	// same refusal as a disagreeing one.
	if rep.ClientID == nil || *rep.ClientID != client.ClientID {
		httpx.WriteOAuthError(w, http.StatusBadRequest,
			errInvalidClientMeta, descClientIdentifierModified)
		return
	}
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}
	// The secret survives an update, measured: a PUT answered with the same
	// client_secret the create minted. applyRegistration mints one only when
	// the client has none.
	if !applyRegistration(w, client, rep) {
		return
	}
	if err := h.store.Clients().Update(r.Context(), client); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	rat, err := h.mintRegistrationToken(realm, client, k)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK, h.registrationBody(realm, client, rat))
}

// deleteRegisteredClient serves DELETE on the item path.
//
// The 204 carries four of the five security headers, and that falls out of
// httpx.WriteNoContent rather than being decided here: a DELETE sends no
// Content-Type, so X-Frame-Options is omitted. The same request with an
// application/* Content-Type carries it.
func (h *handler) deleteRegisteredClient(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	client, _, ok := h.authorizeRegistered(w, r, realm, true)
	if !ok {
		return
	}
	if err := h.store.Clients().Delete(r.Context(), realm.ID, client.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.registrations.forget(realm.ID, client.ID)
	httpx.WriteNoContent(w, r)
}

// registrationCaller is who is asking. The three states refuse differently,
// which is why this is not a bool.
type registrationCaller struct {
	// anonymous is a request carrying no usable credential: no bearer token at
	// all, `Bearer ` with nothing after it, Basic credentials, or a valid
	// registration access token belonging to another client. Measured: all four
	// get the credential-less refusal rather than a decode failure.
	anonymous bool
	// admin says the bearer was an access token this server issued, whether or
	// not it opens anything. It is what separates the 403 an administrator
	// without the role gets from the 401 a stranger gets.
	admin bool
	// holder means the presented token is the current registration access token
	// of the client in the path.
	holder bool
	// grants are the caller's admin role names on the client that governs the
	// realm in the path, empty for a caller holding none.
	grants map[string]bool
	// presented is the raw bearer, kept so a holder's read can echo it.
	presented string
}

func (c *registrationCaller) mayCreate() bool {
	return c.grants[registrationRoleCreate] || c.grants[registrationRoleManage]
}

func (c *registrationCaller) mayRead() bool {
	return c.holder || c.grants[registrationRoleView] || c.grants[registrationRoleManage]
}

func (c *registrationCaller) mayWrite() bool {
	return c.holder || c.grants[registrationRoleManage]
}

// writeRegistrationRefusal is the refusal for a caller that may not act, and it
// is three bodies rather than one.
//
// An anonymous caller on the collection is told about the client registration
// policy a default realm has; an anonymous caller on an item is told it is not
// authorised, in one of two sentences chosen by the verb; and an authenticated
// administrator holding the wrong role is told `Forbidden`, with a different
// status. Collapsing any pair loses the only externally visible difference
// between "anonymous registration is switched off" and "you are not an
// administrator".
func writeRegistrationRefusal(w http.ResponseWriter, c *registrationCaller, item bool) {
	switch {
	case c.anonymous && !item:
		httpx.WriteOAuthError(w, http.StatusForbidden, errInsufficientScope, descTrustedHosts)
	case c.anonymous:
		httpx.WriteOAuthError(w, http.StatusUnauthorized, errInvalidToken, descNotAuthorizedView)
	default:
		httpx.WriteOAuthError(w, http.StatusForbidden, errInsufficientScope, descForbidden)
	}
}

// authorizeRegistered runs the item path's ladder past the realm: the bearer,
// the authorisation and finally the client.
//
// **The client is looked up before the caller's role is judged and after the
// caller is authenticated**, which is measured on the four cells that tell the
// three possible orders apart:
//
//	missing client, no bearer          401  (not the 404)
//	missing client, view-clients       404
//	missing client, no admin role      403
//	present client, another's token    401
//
// So a caller who proves nothing never learns whether the client exists, and a
// caller who proves something but may not act does not either.
func (h *handler) authorizeRegistered(w http.ResponseWriter, r *http.Request,
	realm *model.Realm, write bool) (*model.Client, *registrationCaller, bool) {
	client, err := h.store.Clients().ByClientID(r.Context(), realm.ID, r.PathValue("clientId"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, nil, false
	}
	caller, ok := h.registrationCaller(w, r, realm, client)
	if !ok {
		return nil, nil, false
	}
	allowed := caller.mayRead()
	if write {
		allowed = caller.mayWrite()
	}
	if !allowed {
		if caller.anonymous && write {
			httpx.WriteOAuthError(w, http.StatusUnauthorized, errInvalidToken, descNotAuthorizedUpdate)
			return nil, nil, false
		}
		writeRegistrationRefusal(w, caller, true)
		return nil, nil, false
	}
	if client == nil {
		httpx.WriteOAuthError(w, http.StatusNotFound, authErrInvalidRequest, descClientNotFound)
		return nil, nil, false
	}
	return client, caller, true
}

// registrationCaller resolves the Authorization header.
//
// The order is measured. A bearer that does not verify is `Failed decode
// token`, and the word covers more than it says: a **well-formed JWT with a
// wrong signature** answers it, not only unparseable input. A bearer that
// verifies as the wrong kind of token - a refresh token - is `Invalid type of
// token` instead.
func (h *handler) registrationCaller(w http.ResponseWriter, r *http.Request,
	realm *model.Realm, client *model.Client) (*registrationCaller, bool) {
	raw := registrationBearer(r)
	if raw == "" {
		return &registrationCaller{anonymous: true}, true
	}
	k, err := h.keys.ForRealm(r.Context(), realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}

	// A registration access token first: it is the credential this endpoint
	// mints, and the only one that opens an item without an admin role.
	if jti, err := token.ParseRegistration(k, h.realmIssuer(realm.Name), raw); err == nil {
		c := &registrationCaller{presented: raw}
		if client != nil && h.registrations.holds(realm.ID, client.ID, jti) {
			c.holder = true
		} else {
			// A token that verifies but names another client - or one whose
			// client has gone - answers the same 401 a caller with no token
			// gets, so it is reported as anonymous rather than as a decode
			// failure. Measured on both.
			c.anonymous = true
		}
		return c, true
	}
	return h.registrationAdmin(w, r, raw)
}

// registrationAdmin turns a bearer into an administrator, or writes the
// measured 401 and reports that it wrote one.
//
// It resolves the token in **the realm that issued it**, the same order
// internal/admin's authenticate uses and for the same measured reason: a token
// from another realm has to fail closed rather than be verified against the
// wrong key.
func (h *handler) registrationAdmin(w http.ResponseWriter, r *http.Request, raw string) (
	*registrationCaller, bool) {
	refuse := func(desc string) (*registrationCaller, bool) {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, errInvalidToken, desc)
		return nil, false
	}
	iss, err := token.UnverifiedIssuer(raw)
	if err != nil {
		return refuse(descFailedDecode)
	}
	name, ok := strings.CutPrefix(iss, h.issuerBase+"/realms/")
	if !ok || name == "" || strings.Contains(name, "/") {
		return refuse(descFailedDecode)
	}
	authRealm, err := h.store.Realms().ByName(r.Context(), name)
	if err != nil {
		return refuse(descFailedDecode)
	}
	ak, err := h.keys.ForRealm(r.Context(), authRealm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	authIssuer := h.realmIssuer(authRealm.Name)
	parsed, err := token.ParseAccess(ak, authIssuer, raw, time.Now())
	if err != nil {
		// A refresh token verifies against the same realm and is the wrong
		// kind; everything else is a decode failure.
		if _, refreshErr := token.ParseRefresh(ak, authIssuer, raw, time.Now()); refreshErr == nil {
			return refuse(descInvalidTokenType)
		}
		return refuse(descFailedDecode)
	}
	session, err := h.store.Sessions().UserSessionByID(r.Context(), authRealm.ID, parsed.SessionID)
	if err != nil {
		return refuse(descFailedDecode)
	}
	user, err := h.store.Users().ByID(r.Context(), authRealm.ID, session.UserID)
	if err != nil || !user.Enabled {
		return refuse(descFailedDecode)
	}
	grants, err := h.registrationGrants(r, authRealm, r.PathValue("realm"), user)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return &registrationCaller{admin: true, grants: grants, presented: raw}, true
}

// registrationGrants is which admin role names this caller holds on the client
// that governs the realm in the path.
//
// **Only the master-administering-master cell is measured on this endpoint**,
// because it is the only one a default container reaches without creating a
// second realm. The three-way resolution is the one internal/admin's
// containerFor already records and is reproduced rather than re-derived, so the
// two cannot answer differently about a caller they both see.
func (h *handler) registrationGrants(r *http.Request, authRealm *model.Realm,
	targetRealm string, user *model.User) (map[string]bool, error) {
	var containerName string
	switch {
	case authRealm.Name == bootstrap.MasterRealmName && targetRealm == bootstrap.MasterRealmName:
		containerName = bootstrap.AdminContainerFor(bootstrap.MasterRealmName)
	case authRealm.Name == bootstrap.MasterRealmName:
		containerName = targetRealm + "-realm"
	case authRealm.Name == targetRealm:
		containerName = bootstrap.AdminContainerFor(targetRealm)
	default:
		return nil, nil
	}
	container, err := h.store.Clients().ByClientID(r.Context(), authRealm.ID, containerName)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	effective, err := roles.Effective(r.Context(), h.store.Roles(), user.ID)
	if err != nil {
		return nil, err
	}
	grants := map[string]bool{}
	for _, role := range effective {
		if role.ClientID == container.ID {
			grants[role.Name] = true
		}
	}
	return grants, nil
}

// registrationBearer is the Authorization header's bearer token, empty when
// there is none. An empty value after "Bearer " counts as none, measured: it
// gets the anonymous refusal rather than a decode failure.
func registrationBearer(r *http.Request) string {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(raw)
}

// decodeRegistration reads the body.
//
// **Both of its refusals run before the caller is looked at**, which is the
// order this endpoint measured and the opposite of every other guarded route in
// this project: a request with no Content-Type and no credentials answers 415,
// and one carrying `{` and no credentials answers 400.
func decodeRegistration(w http.ResponseWriter, r *http.Request) (registrationRequest, bool) {
	var rep registrationRequest
	if !registrationConsumes(r.Header.Get("Content-Type")) {
		httpx.WriteMessageError(w, http.StatusUnsupportedMediaType, descUnsupportedMediaType)
		return rep, false
	}
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descCannotParseJSON)
		return rep, false
	}
	return rep, true
}

// registrationConsumes is what the 415 is decided by, and it is a **media type
// match rather than a prefix**. Measured over eight Content-Type values on one
// request:
//
//	(the header absent)                 accepted
//	application/json                    accepted
//	application/json;charset=UTF-8      accepted
//	application/JSON                    accepted - the comparison folds case
//	*/*                                 accepted
//	application/x-www-form-urlencoded   415
//	text/plain                          415
//	application/xml                     415
//	application/jsonx                   415 - so it is not a prefix
//
// **An absent header is accepted**, which is the row a "must be JSON" check gets
// wrong, and it is how the conformance harness reaches this endpoint at all:
// buildRequest sets no Content-Type for a case sending a Body.
//
// One input is not reproduced. A header present with an **empty value** was
// measured answering a 500 serving Keycloak's HTML error page with an error id
// in it, which is neither of this endpoint's two body shapes; Go's Header.Get
// cannot tell it from an absent header without reading the map directly, and an
// HTML 500 is not a contract this project has anywhere else. Filed rather than
// guessed at.
func registrationConsumes(value string) bool {
	if value == "" {
		return true
	}
	media, _, _ := strings.Cut(value, ";")
	switch strings.ToLower(strings.TrimSpace(media)) {
	case "application/json", "*/*":
		return true
	}
	return false
}

// applyRegistration writes a request onto a client, returning false when it has
// already written a refusal.
//
// It is a **replacement** rather than a merge, on the create and the update
// alike: a PUT omitting redirect_uris was measured leaving the client with
// none. That is the opposite of PUT /admin/realms/{r}/clients/{uuid}, which
// merges - two write paths onto one resource, and the obvious shared helper is
// wrong on one of them.
func applyRegistration(w http.ResponseWriter, c *model.Client, rep registrationRequest) bool {
	c.Name = deref(rep.ClientName)
	c.BaseURL = deref(rep.ClientURI)
	c.RedirectURIs = derefSlice(rep.RedirectURIs)
	if rep.PostLogoutRedirectURIs != nil {
		c.Attributes[attrPostLogoutURIs] = strings.Join(*rep.PostLogoutRedirectURIs, "##")
	} else {
		delete(c.Attributes, attrPostLogoutURIs)
	}
	if !applyRegistrationAuthMethod(w, c, rep.TokenEndpointAuthMethod) {
		return false
	}
	applyRegistrationFlows(c, rep)
	c.Attributes[attrDPoPBound] = boolAttribute(rep.DPoPBoundAccessTokens != nil && *rep.DPoPBoundAccessTokens)
	c.Attributes[attrTLSBound] = boolAttribute(
		rep.TLSClientCertificateBoundAccessTokens != nil && *rep.TLSClientCertificateBoundAccessTokens)
	c.Attributes[attrRequirePAR] = boolAttribute(
		rep.RequirePushedAuthorizationRequests != nil && *rep.RequirePushedAuthorizationRequests)
	// **backchannel.logout.session.required is written "true" and read back
	// false.** A registered client carries the attribute set, and this
	// endpoint's own view of it is a constant false whatever the attribute
	// says - measured on seven inputs, including a request body naming the
	// field true and a client with a backchannel logout URL. The two
	// session.required attributes are not a pair here: its neighbour does
	// follow its attribute, with the opposite default.
	c.Attributes[attrBackchannelSess] = "true"
	c.Attributes[attrBackchannelRevo] = "false"
	c.Attributes[attrFrontchannelSess] = boolAttribute(
		rep.FrontchannelLogoutSessionRequired != nil && *rep.FrontchannelLogoutSessionRequired)
	c.Attributes[attrRealmClient] = "false"
	if c.Secret == "" && !c.PublicClient && clientCarriesSecret(c) {
		c.Secret = model.NewSecret()
		c.Attributes[attrSecretCreated] = strconv.FormatInt(time.Now().Unix(), 10)
	}
	return true
}

func boolAttribute(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefSlice(s *[]string) []string {
	if s == nil || *s == nil {
		return []string{}
	}
	return *s
}

// applyRegistrationAuthMethod maps token_endpoint_auth_method onto the client's
// authenticator, refusing the spellings measured to be refused.
func applyRegistrationAuthMethod(w http.ResponseWriter, c *model.Client, method *string) bool {
	delete(c.Attributes, attrSecretMethod)
	if method == nil {
		c.ClientAuthenticatorType = authenticatorSecret
		c.PublicClient = false
		return true
	}
	switch *method {
	case authMethodSecretBasic, authMethodSecretPost:
		c.ClientAuthenticatorType = authenticatorSecret
		c.PublicClient = false
		c.Attributes[attrSecretMethod] = *method
	case authMethodSecretJWT:
		c.ClientAuthenticatorType = authenticatorSecretJWT
		c.PublicClient = false
	case authMethodTLS:
		c.ClientAuthenticatorType = authenticatorX509
		c.PublicClient = false
	case authMethodNone:
		c.ClientAuthenticatorType = authenticatorNone
		c.PublicClient = true
	default:
		// private_key_jwt is in here, and it is the surprise: the discovery
		// document advertises it and this endpoint emits it, and it cannot be
		// asked for.
		httpx.WriteOAuthError(w, http.StatusBadRequest,
			errInvalidClientMeta, descClientMetadataInvalid)
		return false
	}
	return true
}

// applyRegistrationFlows turns grant_types and response_types into the four
// flow flags and the five attributes. Measured over nine bodies:
//
//	(nothing)                        standard
//	grant_types []                   standard, and use.refresh.tokens off
//	grant_types [authorization_code] standard
//	grant_types [refresh_token]      no flow at all
//	grant_types [password]           direct access
//	grant_types [client_credentials] service accounts
//	grant_types [implicit]           implicit
//	response_types [code]            standard
//	response_types [token,id_token]  implicit, and standard **off**
//
// The empty array is the one that says the two halves are separate: it leaves
// the flow flags at their defaults and still turns refresh tokens off.
func applyRegistrationFlows(c *model.Client, rep registrationRequest) {
	c.StandardFlowEnabled = true
	c.ImplicitFlowEnabled = false
	c.DirectAccessGrantsEnabled = false
	c.ServiceAccountsEnabled = false
	if rep.ResponseTypes != nil && len(*rep.ResponseTypes) > 0 {
		types := *rep.ResponseTypes
		c.StandardFlowEnabled = slices.Contains(types, "code") || slices.Contains(types, "none")
		c.ImplicitFlowEnabled = slices.Contains(types, "id_token") || slices.Contains(types, "token")
	}
	if rep.GrantTypes == nil {
		for _, name := range []string{attrUseRefreshTokens, attrDeviceGrant, attrCIBAGrant,
			attrExchangeGrant, attrJWTBearerGrant} {
			delete(c.Attributes, name)
		}
		return
	}
	types := *rep.GrantTypes
	if len(types) > 0 {
		c.StandardFlowEnabled = slices.Contains(types, grantTypeAuthorizationCode)
		c.ImplicitFlowEnabled = slices.Contains(types, grantTypeImplicit)
	}
	c.DirectAccessGrantsEnabled = slices.Contains(types, grantTypePassword)
	c.ServiceAccountsEnabled = slices.Contains(types, grantTypeClientCredentials)
	// Naming grant_types writes five attributes, not one: the four grants that
	// have no flow flag of their own, plus whether refresh tokens are used.
	// So **dynamic registration is a second way to switch on the device grant,
	// CIBA, token exchange and the JWT bearer grant**, measured.
	c.Attributes[attrUseRefreshTokens] = boolAttribute(slices.Contains(types, grantRefreshToken))
	c.Attributes[attrDeviceGrant] = boolAttribute(slices.Contains(types, grantDeviceCode))
	c.Attributes[attrCIBAGrant] = boolAttribute(slices.Contains(types, grantCIBA))
	c.Attributes[attrExchangeGrant] = boolAttribute(slices.Contains(types, grantTokenExchange))
	c.Attributes[attrJWTBearerGrant] = boolAttribute(slices.Contains(types, grantJWTBearer))
}

// mintRegistrationToken issues a registration access token and makes it the
// current one, which is what a PUT's rotation is.
func (h *handler) mintRegistrationToken(realm *model.Realm, c *model.Client, k *keys.RealmKeys) (string, error) {
	jti := model.NewID()
	rat, err := token.IssueRegistration(k, h.realmIssuer(realm.Name), jti, time.Now())
	if err != nil {
		return "", err
	}
	h.registrations.issue(realm.ID, c.ID, jti)
	return rat, nil
}

func (h *handler) registrationURI(realm, clientID string) string {
	return h.realmBase(realm) + "/clients-registrations/" + registrationProvider + "/" + clientID
}

// registrationBody renders a client in the OIDC registration shape.
func (h *handler) registrationBody(realm *model.Realm, c *model.Client, rat string) oidcClientRepresentation {
	method := registrationAuthMethod(c)
	body := oidcClientRepresentation{
		RedirectURIs:            nonEmptyStrings(c.RedirectURIs),
		TokenEndpointAuthMethod: method,
		GrantTypes:              registrationGrantTypes(c),
		ResponseTypes:           registrationResponseTypes(c),
		ClientID:                c.ClientID,
		ClientName:              c.Name,
		ClientURI:               c.BaseURL,
		// scope is the client's **optional** client scopes joined by spaces, in
		// the realm's order rather than the request's: "email profile" goes in
		// and "profile email" comes back.
		Scope:                                 strings.Join(c.OptionalClientScopes, " "),
		SubjectType:                           "public",
		RequestURIs:                           []string{},
		TLSClientCertificateBoundAccessTokens: c.Attributes[attrTLSBound] == "true",
		DPoPBoundAccessTokens:                 c.Attributes[attrDPoPBound] == "true",
		PostLogoutRedirectURIs:                registrationPostLogoutURIs(c),
		RegistrationClientURI:                 h.registrationURI(realm.Name, c.ClientID),
		RegistrationAccessToken:               rat,
		// Constant false, measured. See applyRegistration.
		BackchannelLogoutSessionRequired:   false,
		RequirePushedAuthorizationRequests: c.Attributes[attrRequirePAR] == "true",
		// This one **does** read its attribute, and its default is the
		// opposite: absent behaves as true.
		FrontchannelLogoutSessionRequired: c.Attributes[attrFrontchannelSess] != "false",
	}
	if methodCarriesSecret(method) {
		zero := 0
		body.ClientSecretExpiresAt = &zero
		if !c.PublicClient {
			body.ClientSecret = c.Secret
		}
	}
	return body
}

// methodCarriesSecret says whether client_secret_expires_at is emitted.
//
// Measured over seven clients: the three secret-carrying methods emit it, and
// tls_client_auth, private_key_jwt and none do not - **whether or not the
// client is public**. admin-cli is public, carries the expiry and carries no
// secret, which is the pair that says the two keys are decided separately.
func methodCarriesSecret(method string) bool {
	return method == authMethodSecretBasic || method == authMethodSecretPost || method == authMethodSecretJWT
}

func clientCarriesSecret(c *model.Client) bool {
	return methodCarriesSecret(registrationAuthMethod(c))
}

// registrationAuthMethod is the read direction, and it is decided by
// clientAuthenticatorType and **not** by publicClient: `admin-cli` is public
// and reads back client_secret_basic.
func registrationAuthMethod(c *model.Client) string {
	switch c.ClientAuthenticatorType {
	case authenticatorNone:
		return authMethodNone
	case authenticatorSecretJWT:
		return authMethodSecretJWT
	case authenticatorX509:
		return authMethodTLS
	case authenticatorJWT:
		return authMethodPrivateJWT
	default:
		if m := c.Attributes[attrSecretMethod]; m != "" {
			return m
		}
		return authMethodSecretBasic
	}
}

// registrationGrantTypes is the measured order, and **refresh_token is seventh
// of nine** rather than last:
//
//	authorization_code, implicit, password, client_credentials,
//	urn:…:device_code, urn:openid:…:ciba, refresh_token,
//	urn:…:token-exchange, urn:…:jwt-bearer
//
// Read off a client with all nine on, and again with use.refresh.tokens off so
// the position of the one that moves is fixed rather than inferred.
func registrationGrantTypes(c *model.Client) []string {
	out := []string{}
	if c.StandardFlowEnabled {
		out = append(out, grantTypeAuthorizationCode)
	}
	if c.ImplicitFlowEnabled {
		out = append(out, grantTypeImplicit)
	}
	if c.DirectAccessGrantsEnabled {
		out = append(out, grantTypePassword)
	}
	if c.ServiceAccountsEnabled {
		out = append(out, grantTypeClientCredentials)
	}
	if c.Attributes[attrDeviceGrant] == "true" {
		out = append(out, grantDeviceCode)
	}
	if c.Attributes[attrCIBAGrant] == "true" {
		out = append(out, grantCIBA)
	}
	if c.Attributes[attrUseRefreshTokens] != "false" {
		out = append(out, grantRefreshToken)
	}
	if c.Attributes[attrExchangeGrant] == "true" {
		out = append(out, grantTokenExchange)
	}
	if c.Attributes[attrJWTBearerGrant] == "true" {
		out = append(out, grantJWTBearer)
	}
	return out
}

// registrationResponseTypes is derived from the two browser flow flags, and the
// three combined spellings appear only when **both** are on.
func registrationResponseTypes(c *model.Client) []string {
	out := []string{}
	if c.StandardFlowEnabled {
		out = append(out, "code", "none")
	}
	if c.ImplicitFlowEnabled {
		out = append(out, "id_token", "id_token token")
	}
	if c.StandardFlowEnabled && c.ImplicitFlowEnabled {
		out = append(out, "code id_token", "code token", "code id_token token")
	}
	return out
}

// registrationPostLogoutURIs reads the client's post.logout.redirect.uris
// attribute, whose ## separator is the one the logout endpoint already reads. A
// client with no attribute answers its own redirect URIs, which is the filter
// rule that attribute carries there too.
func registrationPostLogoutURIs(c *model.Client) []string {
	raw, ok := c.Attributes[attrPostLogoutURIs]
	if !ok || raw == "" || raw == "+" {
		return nonEmptyStrings(c.RedirectURIs)
	}
	return strings.Split(raw, "##")
}

func nonEmptyStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

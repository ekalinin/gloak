package oidc

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The OAuth 2.0 Device Authorization Grant, RFC 8628: the endpoint that mints a
// device_code and the token endpoint's grant that redeems one.
//
// Everything here was measured against a live Keycloak 26.7.1 on 2026-08-30.
// See docs/superpowers/plans/2026-08-30-p7-device-grant.md sections 1.1 and 1.2
// for the probes, including the pairs that decided each adjacency.

// grantDeviceCode is the grant_type this endpoint's codes are redeemed under.
// It is already in the discovery document's grant_types_supported.
const grantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

// The three client attributes that configure the grant. All three are measured:
// creating a client with each and reading what the device endpoint answered.
//
// `oauth2DeviceCodeLifespan` - the realm field's spelling - was measured as a
// client attribute too and does nothing, which is the obvious wrong guess and
// so is worth having been checked.
const (
	attrDeviceGrantEnabled = "oauth2.device.authorization.grant.enabled"
	attrDeviceCodeLifespan = "oauth2.device.code.lifespan"
	attrDevicePollInterval = "oauth2.device.polling.interval"
)

// The realm's two defaults, measured on master: oauth2DeviceCodeLifespan 600
// and oauth2DevicePollingInterval 5.
//
// They are constants here rather than realm fields because internal/model is
// not this cut's package. A realm that has had them changed through
// PUT /admin/realms/{realm} will diverge; the client attributes above override
// them and are what the conformance cases use, so nothing recorded rests on
// these two numbers being configurable.
const (
	defaultDeviceCodeLifespan = 600 * time.Second
	defaultDevicePollInterval = 5 * time.Second
)

// The device grant's measured error descriptions.
//
// **The two "this client may not use this grant" answers are not one string and
// not one code**, and that is the single most reusable-looking thing here.
// Measured side by side on one container:
//
//	POST .../auth/device   400  unauthorized_client  Client is not allowed to initiate OAuth 2.0
//	                                                 Device Authorization Grant. The flow is
//	                                                 disabled for the client.
//	POST .../token         400  invalid_grant        Client not allowed OAuth 2.0 Device
//	                                                 Authorization Grant
//
// One condition, two endpoints, a different code and a different sentence.
// Folding them into one constant passes both happy paths and gets both
// rejections wrong.
const (
	descDeviceGrantOffAtDevice = "Client is not allowed to initiate OAuth 2.0 Device " +
		"Authorization Grant. The flow is disabled for the client."
	descDeviceGrantOffAtToken = "Client not allowed OAuth 2.0 Device Authorization Grant"
	descMissingDeviceCode     = "Missing parameter: device_code"
	descDeviceCodeNotValid    = "Device code not valid"
	descDeviceCodeExpired     = "Device code is expired"
	// Lower case and two words, where the authorization code grant's equivalent
	// is "Auth error: Found different client_id in clientSession". Measured with
	// two **public** grant-enabled clients, so nothing but the code differs -
	// the observed document records that the same probe run with a confidential
	// client once measured client authentication by mistake.
	descDeviceWrongClient    = "unauthorized client"
	descSlowDown             = "Slow down"
	descAccessDenied         = "The end user denied the authorization request"
	descAuthorizationPending = "The authorization request is still pending"
)

// The device grant's error codes. Four of them appear nowhere else in Gloak.
const (
	deviceErrAuthorizationPending = "authorization_pending"
	deviceErrSlowDown             = "slow_down"
	deviceErrExpiredToken         = "expired_token"
	deviceErrAccessDenied         = "access_denied"
)

// deviceAuthorizationCacheControl is the one header this endpoint's **success**
// carries and its rejections do not.
//
// That is the opposite way round from the token endpoint, where every response
// including every rejection carries Cache-Control: no-store and
// Pragma: no-cache. This endpoint sends no Pragma at all, on any response, and
// no Cache-Control on any rejection. Measured across the 200 and all five
// refusals on one container.
const deviceAuthorizationCacheControl = "no-store, must-revalidate, max-age=0"

// deviceAuthorizationResponse is the success body, in the measured key order.
//
// verification_uri_complete is the verification_uri with the user_code on the
// query, which is the shape a QR code carries. Nothing here is omitempty: all
// six keys were present on every measured 200.
type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// deviceAuthorization serves POST /realms/{realm}/protocol/openid-connect/auth/device.
//
// The order is measured, one pair of faults per adjacency:
//
//	1. the realm             404 Realm does not exist   - beats an unknown client
//	2. client authentication 401                        - beats the duplicate check
//	3. a duplicated form key 400 invalid_grant          - beats the grant flag
//	4. the grant flag        400 unauthorized_client
//
// **The scope is not checked at all.** scope=bogus-scope and an empty scope=
// both answer 200 here, where GET /auth refuses both. And the duplicate check
// reads the **body only**: the same key twice on the query answered 200.
func (h *handler) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, "Invalid request")
		return
	}
	client, authErr := h.authenticateClient(r.Context(), realm, r.PostForm, r.Header)
	if authErr != nil {
		authErr.write(w)
		return
	}
	// invalid_grant, where the token endpoint spells the identical description
	// invalid_request. Two endpoints in one flow, one container, two codes.
	if hasDuplicate(r.PostForm) {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descDuplicatedParameter)
		return
	}
	if !deviceGrantEnabled(client) {
		httpx.WriteOAuthError(w, http.StatusBadRequest,
			authErrUnauthorizedClient, descDeviceGrantOffAtDevice)
		return
	}

	lifespan := deviceCodeLifespan(client)
	interval := devicePollInterval(client)
	dc, err := h.device.newDeviceCode(&deviceCode{
		Realm:      realm.Name,
		ClientUUID: client.ID,
		Scope:      grantedScope(r.PostForm.Get("scope")),
		Interval:   interval,
	}, lifespan)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	verificationURI := h.realmBase(realm.Name) + "/device"
	w.Header().Set("Cache-Control", deviceAuthorizationCacheControl)
	httpx.WriteJSON(w, http.StatusOK, deviceAuthorizationResponse{
		DeviceCode:              dc.Code,
		UserCode:                dc.UserCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURI + "?user_code=" + dc.UserCode,
		ExpiresIn:               int64(lifespan.Seconds()),
		Interval:                int64(interval.Seconds()),
	})
}

// deviceCodeGrant redeems a device_code at the token endpoint.
//
// grant_type, client authentication and the duplicated-parameter check have
// already run in token(); the measured order puts all three in front of
// everything below, and the duplicate check in front of the grant flag - a
// grant-disabled client sending a key twice is told about the key.
//
// The six adjacencies below were each measured by driving two faults at once,
// and four of them are not where they look. See the plan's section 1.2.
func (h *handler) deviceCodeGrant(w http.ResponseWriter, r *http.Request,
	realm *model.Realm, client *model.Client, k *keys.RealmKeys) {
	if !deviceGrantEnabled(client) {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descDeviceGrantOffAtToken)
		return
	}
	// Presence, not value: an empty device_code= reaches the lookup and answers
	// "Device code not valid", where an absent one answers about the parameter.
	// The same split the authorization code grant measures for `code`.
	if _, present := r.PostForm["device_code"]; !present {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descMissingDeviceCode)
		return
	}
	dc, ok := h.device.deviceCodeByCode(realm.Name, r.PostForm.Get("device_code"))
	if !ok {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descDeviceCodeNotValid)
		return
	}
	// Expiry beats the poll interval. Measured: an expired code polled twice in
	// a row inside a ten-second interval answered expired_token both times,
	// where a pending code answers slow_down on the second.
	if time.Now().After(dc.ExpiresAt) {
		httpx.WriteOAuthError(w, http.StatusBadRequest, deviceErrExpiredToken, descDeviceCodeExpired)
		return
	}
	// The client match beats the poll interval too, and it measurably does not
	// stamp the clock: three wrong-client polls in a row, then the right client
	// immediately, answered authorization_pending rather than slow_down.
	if dc.ClientUUID != client.ID {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descDeviceWrongClient)
		return
	}
	// slow_down does **not** move LastPoll. Polls at t=0, t=3 and t=6 with
	// interval 5 answered pending, slow_down, pending; stamping here would
	// answer slow_down at t=6.
	if !dc.LastPoll.IsZero() && time.Since(dc.LastPoll) < dc.Interval {
		httpx.WriteOAuthError(w, http.StatusBadRequest, deviceErrSlowDown, descSlowDown)
		return
	}
	h.device.stampPoll(dc)

	// A denied code is **not** consumed by the poll that reports it: measured,
	// it answered access_denied again six and twelve seconds later.
	if dc.Denied {
		httpx.WriteOAuthError(w, http.StatusBadRequest, deviceErrAccessDenied, descAccessDenied)
		return
	}
	if dc.UserID == "" {
		httpx.WriteOAuthError(w, http.StatusBadRequest,
			deviceErrAuthorizationPending, descAuthorizationPending)
		return
	}
	h.completeDeviceCode(w, r, realm, client, k, dc)
}

// completeDeviceCode exchanges an approved device code for a token set.
//
// The code is spent first and unconditionally, the way the authorization code
// grant spends its own: measured, the poll after a successful exchange answers
// "Device code not valid", so a redeemed code and one that never existed are
// the same answer.
//
// auth_time is the session's start, which is what the measured access token
// carries - the device grant's success body is the ordinary nine keys with
// auth_time and acr present, byte-compatible with the authorization code
// grant's.
//
// Nothing in this cut approves a device code, because approving one means the
// verification page and the consent page, which are cut B. The path is built
// and unit-tested through deviceStore.approveDeviceCode so that cut B adds
// pages rather than a grant.
func (h *handler) completeDeviceCode(w http.ResponseWriter, r *http.Request,
	realm *model.Realm, client *model.Client, k *keys.RealmKeys, dc *deviceCode) {
	h.device.spendDeviceCode(dc)

	ctx := r.Context()
	session, err := h.store.Sessions().UserSessionByID(ctx, realm.ID, dc.SessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descDeviceCodeNotValid)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	user, err := h.store.Users().ByID(ctx, realm.ID, dc.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descDeviceCodeNotValid)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.writeTokens(w, r, realm, client, user, session, dc.Scope, k, false,
		time.UnixMilli(session.StartedAt), "")
}

// deviceGrantEnabled reads the client attribute both endpoints gate on.
//
// It is off on every client of a default 26.7.1 - all six bootstrapped ones -
// which is why the catalogue's device cases measured a refusal until this cut
// gave them a client that has it.
func deviceGrantEnabled(c *model.Client) bool {
	return c.Attributes[attrDeviceGrantEnabled] == "true"
}

// deviceCodeLifespan and devicePollInterval are the client overrides, falling
// back to the realm's measured defaults.
//
// Both were found by creating a client with each attribute and reading
// expires_in and interval off the 200. Neither is written down anywhere else in
// this repository, and the second is what makes the expired-token case
// recordable at all: without it, reaching an expired device code means a
// PUT on the realm, which would move oauth2DeviceCodeLifespan for every case
// recorded afterwards in a shared-container run.
func deviceCodeLifespan(c *model.Client) time.Duration {
	return deviceDurationAttr(c, attrDeviceCodeLifespan, defaultDeviceCodeLifespan)
}

func devicePollInterval(c *model.Client) time.Duration {
	return deviceDurationAttr(c, attrDevicePollInterval, defaultDevicePollInterval)
}

// deviceDurationAttr reads a whole number of seconds off a client attribute.
//
// A non-numeric or non-positive value falls back to the default. That is
// deliberately the same rule accessLifespan already applies, and it is
// **unmeasured for these two attributes**: only positive values were sent.
func deviceDurationAttr(c *model.Client, name string, fallback time.Duration) time.Duration {
	seconds, err := strconv.Atoi(c.Attributes[name])
	if err != nil || seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/token"
)

// Back-channel and front-channel logout: the two ways a logout reaches the
// other clients a session was used at.
//
// Measured 2026-08-31 against a live 26.7.1, container kc-logout on 8132, with
// a listener in a second container on the same bridge. See
// docs/superpowers/plans/2026-08-31-p6-channel-logout.md for how an outbound
// call is measured at all - it is the first thing this project has had to
// observe that Keycloak does without being asked.
//
// The two mechanisms look symmetrical and are not:
//
//   - **Back-channel is Keycloak's own HTTP call**, a POST carrying a signed
//     logout token, made while the session is still alive and with every result
//     thrown away.
//   - **Front-channel is a page**, and the *browser* makes the calls. Keycloak's
//     part is a 200 with an iframe per client, which replaces the 302 the same
//     request would otherwise get.
//
// Four attribute names decide it, and **the two `session.required` attributes
// have opposite defaults**. Measured on clients differing only in that value:
//
//	backchannel.logout.session.required   absent behaves as "false"
//	frontchannel.logout.session.required  absent behaves as "true"
//
// One helper reading both is the tidy-up that gets one of them wrong.
//
// Only the back-channel one is read here. What the front-channel one decides is
// whether the iframe's src gains `?sid=…&iss=…`, and that lives in the page
// body Gloak does not render - it is P13's, and follow-up F113 records it.
const (
	backchannelLogoutURLAttribute                   = "backchannel.logout.url"
	backchannelLogoutSessionAttribute               = "backchannel.logout.session.required"
	frontchannelLogoutURLAttribute                  = "frontchannel.logout.url"
	backchannelLogoutTokenParameter                 = "logout_token"
	backchannelLogoutContentType                    = "application/x-www-form-urlencoded"
	frontchannelLogoutPageTitle                     = logoutConfirmPageTitle
	backchannelLogoutTimeout          time.Duration = 5 * time.Second
)

// channelLogoutTargets is which clients in one session get told about a logout,
// split by mechanism. A client can be in both lists: measured, a session
// holding one front-channel client and one back-channel client got the page
// **and** the outbound call, so the two are not alternatives.
type channelLogoutTargets struct {
	back  []*model.Client
	front []*model.Client
}

// channelLogoutTargets resolves the clients participating in a user session
// that have registered for one of the two mechanisms.
//
// It reads the realm's clients and asks for a client session per candidate,
// rather than listing a session's clients, because internal/oidc sees only the
// store interfaces that exist and SessionRepo has no "list the client sessions
// of this user session". The cost is one query plus one per *registered
// channel-logout client* in the realm, which is zero on every realm this
// project bootstraps - none of the six carries either attribute.
//
// A client that registered a URL but never joined this session is not called.
// Measured: a three-client SSO session with two back-channel clients and one
// plain one produced exactly two calls, and a second session belonging to the
// same user was untouched by a logout naming the first.
func (h *handler) channelLogoutTargets(ctx context.Context, realmID, sessionID string) channelLogoutTargets {
	var targets channelLogoutTargets
	if sessionID == "" {
		return targets
	}
	clients, err := h.store.Clients().ListByRealm(ctx, realmID)
	if err != nil {
		return targets
	}
	for _, c := range clients {
		back := c.Attributes[backchannelLogoutURLAttribute] != ""
		// **Both halves are required for the front channel**, and the flag is
		// a column rather than an attribute. Measured: frontchannelLogout with
		// no URL produces no iframe, and a URL on a client whose flag is false
		// produces none either.
		front := c.FrontchannelLogout && c.Attributes[frontchannelLogoutURLAttribute] != ""
		if !back && !front {
			continue
		}
		if _, err := h.store.Sessions().ClientSession(ctx, sessionID, c.ID); err != nil {
			continue
		}
		if back {
			targets.back = append(targets.back, c)
		}
		if front {
			targets.front = append(targets.front, c)
		}
	}
	return targets
}

// notifyBackchannel POSTs a logout token to every client in clients.
//
// **Every failure is swallowed and there is no retry.** Measured across five
// failing clients - 500, 404, connection refused, an unroutable address and one
// that accepts the socket and never answers - the logout's own status, Location
// and session were identical to a healthy client's every time, and a 500 and a
// 404 each drew exactly one POST. The only observable difference is elapsed
// time: a client holding the socket open blocked the logout for about five
// seconds, twice measured, which is where backchannelLogoutTimeout comes from.
//
// It is called **before** the session is deleted, which is measured rather than
// convenient: with a hanging client holding the socket, the Admin API still
// listed the session. So the notification is sent while what it announces is
// still true.
//
// It is deliberately synchronous. Keycloak's is - the five-second block is what
// says so - and a goroutine here would make a test that reads the listener race
// on something Keycloak does not race on.
func (h *handler) notifyBackchannel(ctx context.Context, k *keys.RealmKeys, realm *model.Realm, sessionID, userID string, clients []*model.Client) {
	if len(clients) == 0 {
		return
	}
	issuer := &token.Issuer{Keys: k, Issuer: h.realmIssuer(realm.Name)}
	for _, c := range clients {
		logoutToken, err := issuer.IssueLogout(token.LogoutRequest{
			ClientID:  c.ClientID,
			UserID:    userID,
			SessionID: sessionID,
			// The client's own choice, and absent means no. See the constant
			// block above for the front channel's opposite default.
			SessionRequired: c.Attributes[backchannelLogoutSessionAttribute] == "true",
		})
		if err != nil {
			continue
		}
		h.postLogoutToken(ctx, c.Attributes[backchannelLogoutURLAttribute], logoutToken)
	}
}

// postLogoutToken sends one notification. The request carries one form key and
// nothing else: measured, no query, no authentication and a Content-Type of
// application/x-www-form-urlencoded with no charset.
func (h *handler) postLogoutToken(ctx context.Context, endpoint, logoutToken string) {
	body := url.Values{backchannelLogoutTokenParameter: {logoutToken}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", backchannelLogoutContentType)
	resp, err := h.backchannelClient().Do(req)
	if err != nil {
		return
	}
	// The status is read and discarded on purpose; see notifyBackchannel.
	_ = resp.Body.Close()
}

// backchannelClient is the outbound client, with the measured timeout. The
// field is nil on a handler nothing has configured, so tests that stand up an
// httptest.NewServer set it and every other caller gets this.
func (h *handler) backchannelClient() *http.Client {
	if h.httpClient != nil {
		return h.httpClient
	}
	return &http.Client{Timeout: backchannelLogoutTimeout}
}

// frontchannelHosts is the frame-src list the front-channel logout page's
// Content-Security-Policy carries: the host and port of each client's
// registered URL, in the order the clients come back, **with duplicates kept**.
// See httpx.FrameSrcPolicy for the measurement that says so.
//
// A URL that does not parse contributes nothing rather than contributing a
// broken entry. Keycloak refuses such a URL at the Admin API - measured, a
// client created with "not a url" is a 400 - so this is a guard against a store
// that already holds one and not a shape anybody can register.
func frontchannelHosts(clients []*model.Client) []string {
	hosts := make([]string, 0, len(clients))
	for _, c := range clients {
		u, err := url.Parse(c.Attributes[frontchannelLogoutURLAttribute])
		if err != nil || u.Host == "" {
			continue
		}
		hosts = append(hosts, u.Host)
	}
	return hosts
}

// This file is the whole of what the browser login reads out of the stored
// authentication flow model, and it is deliberately small.
//
// F103 says the twenty-one Authentication Management operations over that model
// "would let a caller edit a description of something the server does not
// read", and that "the prerequisite for paying it is an execution engine in
// internal/oidc". This is not that engine. It is three named bindings, each
// measured against 26.7.1 before it was written:
//
//	B1  the realm's `browserFlow` selects the top-level flow the login walks.
//	B2  that flow's `auth-username-password-form` execution id is the
//	    `execution` parameter the login form carries.
//	B3  that flow's `auth-cookie` execution's `requirement` decides whether the
//	    SSO short-circuit is attempted at all.
//
// **Nothing else in the model is consulted**, and the exceptions are named in
// internal/admin/flows.go's file comment rather than left for a reader to
// discover. In particular there is no traversal, no requirement algebra and no
// dispatch: `REQUIRED`, `ALTERNATIVE` and `CONDITIONAL` are stored, served and
// never interpreted, and a walk that dispatched into a registry where
// twenty-three of twenty-five authenticators are unimplemented would be a
// louder untruth than the one F103 objects to.

package oidc

import (
	"context"
	"encoding/json"

	"github.com/ekalinin/gloak/internal/model"
)

const (
	// defaultBrowserFlowAlias is what a realm's `browserFlow` holds unless a
	// caller has moved it, and what B1 falls back to when the blob does not
	// name one.
	defaultBrowserFlowAlias = "browser"
	// usernamePasswordAuthenticator is the execution B2 reads. It is the
	// provider id, not a display name.
	usernamePasswordAuthenticator = "auth-username-password-form"
	// cookieAuthenticator is the execution B3 reads.
	cookieAuthenticator = "auth-cookie"
	// requirementDisabled is the only requirement value this package compares
	// against. Every other value means "attempt it", which is a two-valued
	// reading of a four-valued field and is written down as such.
	requirementDisabled = "DISABLED"
)

// browserFlowAlias is B1: the alias of the top-level flow the login walks.
//
// It lives in the realm's Settings blob rather than in a column, with the
// other ninety-nine keys model.Realm does not interpret. Before this cut it was
// served on every realm representation and read by nothing, which is exactly
// the shape F103 names - the entry's own example, shipped.
//
// A blob that will not decode falls back to the default rather than failing the
// login: this decides which flow to look up, and there is no answer to give a
// person instead.
func browserFlowAlias(realm *model.Realm) string {
	if len(realm.Settings) == 0 {
		return defaultBrowserFlowAlias
	}
	var stored struct {
		BrowserFlow *string `json:"browserFlow"`
	}
	if err := json.Unmarshal(realm.Settings, &stored); err != nil {
		return defaultBrowserFlowAlias
	}
	if stored.BrowserFlow == nil || *stored.BrowserFlow == "" {
		return defaultBrowserFlowAlias
	}
	return *stored.BrowserFlow
}

// browserFlowExecution resolves one authenticator's row inside the realm's
// bound browser flow, searching the flow and its sub-flows.
//
// It searches the tree because the two rows this package reads sit at different
// depths: `auth-cookie` is a direct child of `browser` and
// `auth-username-password-form` is inside the `forms` sub-flow. Looking only at
// the direct children would find one and miss the other, which is a bug that
// would have passed every test that used the cookie.
//
// The search is depth-first in priority order, which is the order the
// admin API's own execution listing serves, so "the first one" here and "the
// first one" there are the same row.
func (h *handler) browserFlowExecution(ctx context.Context, realm *model.Realm,
	authenticator string) (*model.AuthenticationExecution, bool) {
	repo := h.store.AuthenticationFlows()
	flows, err := repo.ListFlows(ctx, realm.ID)
	if err != nil {
		return nil, false
	}
	alias := browserFlowAlias(realm)
	byID := make(map[string]*model.AuthenticationFlow, len(flows))
	var root *model.AuthenticationFlow
	for _, f := range flows {
		byID[f.ID] = f
		if f.TopLevel && f.Alias != nil && *f.Alias == alias {
			root = f
		}
	}
	if root == nil {
		return nil, false
	}
	// A bounded walk. The depth limit is not defensive decoration: an execution
	// row's flow pointer is caller-writable through
	// POST /flows/{alias}/executions/flow, and nothing in the schema stops a
	// caller building a cycle.
	seen := make(map[string]bool, len(flows))
	var walk func(flowID string, depth int) (*model.AuthenticationExecution, bool)
	walk = func(flowID string, depth int) (*model.AuthenticationExecution, bool) {
		if depth > len(flows) || seen[flowID] {
			return nil, false
		}
		seen[flowID] = true
		rows, err := repo.ListExecutions(ctx, realm.ID, flowID)
		if err != nil {
			return nil, false
		}
		for _, e := range rows {
			if e.Authenticator == authenticator {
				return e, true
			}
			if e.FlowID != "" && byID[e.FlowID] != nil {
				if found, ok := walk(e.FlowID, depth+1); ok {
					return found, true
				}
			}
		}
		return nil, false
	}
	return walk(root.ID, 0)
}

// loginExecutionID is B2: the `execution` parameter the login form carries and
// the value POST /login-actions/authenticate checks.
//
// Keycloak's value is the id of the `auth-username-password-form` execution
// inside the realm's bound browser flow. Measured directly on two realms of one
// container: each realm's login page emitted exactly that realm's row id, and
// the two differed.
//
// **It falls back to the old hash** when the realm has no seeded flow, no
// `auth-username-password-form` row, or a `browserFlow` naming a flow that does
// not exist. A store written before migration 0030 is the first of those and it
// keeps serving; the other two are states a caller can reach through the admin
// API, and a login that 500s because someone renamed a flow would be a worse
// answer than a stable value.
func (h *handler) loginExecutionID(ctx context.Context, realm *model.Realm) string {
	if e, ok := h.browserFlowExecution(ctx, realm, usernamePasswordAuthenticator); ok {
		return e.ID
	}
	return executionID(realm.ID)
}

// ssoEnabled is B3: whether the cookie is consulted at all.
//
// Keycloak's `auth-cookie` execution at DISABLED means the browser flow does
// not try the cookie, so a request carrying a live KEYCLOAK_IDENTITY renders
// the login page instead of redirecting with a code. Measured in three states
// on one cookie jar - ALTERNATIVE 302, DISABLED 200, ALTERNATIVE 302 again.
//
// A realm with no seeded flow, or whose browser flow has no `auth-cookie` row,
// is **enabled**: that is what every realm did before this cut and what a store
// written before migration 0030 must keep doing.
//
// This reads the requirement as DISABLED or not. REQUIRED, ALTERNATIVE and
// CONDITIONAL are all "attempt it" here, which is not Keycloak's semantics for
// those three and is not claimed to be - see this file's opening comment.
func (h *handler) ssoEnabled(ctx context.Context, realm *model.Realm) bool {
	e, ok := h.browserFlowExecution(ctx, realm, cookieAuthenticator)
	if !ok {
		return true
	}
	return e.Requirement != requirementDisabled
}

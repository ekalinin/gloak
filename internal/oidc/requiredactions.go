package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The required actions a login imposes.
//
// Measured 2026-08-31 against a live 26.7.1, container kc-reqact on 8121; see
// docs/superpowers/plans/2026-08-31-p8-required-actions-at-login.md, whose §1 is
// the state machine this file implements.
//
// Until this file existed a temporary password in Gloak was an ordinary
// password: `internal/admin` wrote UPDATE_PASSWORD onto the user and nothing in
// `internal/oidc` ever read it, so the browser flow answered a code and the
// direct grant answered tokens. Keycloak refuses both. That is F104, whose
// summary named only the admin half.

// The aliases of the required actions a default 26.7.1 realm registers. They are
// spelled here because the table below is keyed by them and a typo in a map key
// is invisible.
const (
	updatePasswordAction   = "UPDATE_PASSWORD"
	updateProfileAction    = "UPDATE_PROFILE"
	verifyEmailAction      = "VERIFY_EMAIL"
	verifyProfileAction    = "VERIFY_PROFILE"
	configureTOTPAction    = "CONFIGURE_TOTP"
	webauthnRegisterAction = "webauthn-register"
	webauthnPasswordless   = "webauthn-register-passwordless"
	recoveryCodesAction    = "CONFIGURE_RECOVERY_AUTHN_CODES"
)

// requiredActionKind is what a login does with one alias, and there are four
// answers rather than the one "show a page" a reader would expect. All four are
// measured, one alias at a time, on a user whose profile was complete and whose
// email was verified:
//
//	actionForm         a page the user has to complete before any token exists
//	actionPlaceholder  a page Keycloak can complete and Gloak cannot
//	actionSelfClears   the login completes and the action is **removed**
//	actionSkipped      the login completes and the action **stays on the user**
//
// The last two are the pair that looks like one case. VERIFY_PROFILE came back
// with `requiredActions: []` after a login that never redirected; delete_credential,
// idp_link and update_user_locale came back still carrying their alias. So
// "Keycloak decided there was nothing to do" is expressed two different ways by
// two neighbouring providers, and a handler that cleared all four would make an
// administrator's idp_link vanish on the first login.
type requiredActionKind int

const (
	actionSkipped requiredActionKind = iota
	actionSelfClears
	actionPlaceholder
	actionForm
)

// requiredActionSpec is one row of the table.
type requiredActionSpec struct {
	kind requiredActionKind
	// title is the measured kc-page-title of the page the action serves, and is
	// empty for the two kinds that serve none.
	title string
}

// requiredActionTable says what Gloak does with each alias a default realm can
// hold. Every row is measured; an alias with no row is skipped, which is
// unreachable in practice because the admin API drops an alias no provider is
// registered under - PUT with ["NOT_A_REAL_ACTION"] answers 204 and the
// representation comes back [].
//
// **TERMS_AND_CONDITIONS, delete_account and UPDATE_EMAIL are absent on
// purpose.** All three are registered and **disabled** on a default realm, so
// the enabled filter in nextRequiredAction is what skips them, and giving them
// rows here would put the same decision in two places. Measured: a user
// carrying only TERMS_AND_CONDITIONS completes the login and the admin
// representation still shows it afterwards.
//
// Three rows are divergences Gloak accepts rather than hides.
// delete_credential, idp_link and update_user_locale are measured to redirect to
// the action endpoint whose landing then redirects **on** to the client, leaving
// the alias on the user; Gloak skips them at the login instead, so it serves one
// 302 fewer and reaches the identical end state - the same code, the same
// cookies, the same stored actions. Reproducing the extra hop would mean
// modelling three providers whose whole behaviour is to decline.
var requiredActionTable = map[string]requiredActionSpec{
	updateProfileAction:    {kind: actionForm, title: httpx.UpdateProfilePageTitle},
	updatePasswordAction:   {kind: actionForm, title: httpx.UpdatePasswordPageTitle},
	configureTOTPAction:    {kind: actionPlaceholder, title: httpx.ConfigureTOTPPageTitle},
	webauthnRegisterAction: {kind: actionPlaceholder, title: httpx.PasskeyPageTitle},
	webauthnPasswordless:   {kind: actionPlaceholder, title: httpx.PasskeyPageTitle},
	recoveryCodesAction:    {kind: actionPlaceholder, title: httpx.RecoveryCodesPageTitle},
	verifyProfileAction:    {kind: actionSelfClears},
	"delete_credential":    {kind: actionSkipped},
	"idp_link":             {kind: actionSkipped},
	"update_user_locale":   {kind: actionSkipped},
	// VERIFY_EMAIL is not in the table because its kind is a function of the
	// user: with emailVerified true the landing clears it and redirects to the
	// client, and with it false the landing is a 500. See verifyEmailStep.
}

// nextRequiredAction is the queue: the aliases the user carries, intersected
// with the realm's **enabled** registered providers, in the provider's
// **priority** order, with the ones that clear themselves cleared on the way.
//
// **Priority decides, not the order of the user's array.** Measured both ways
// round: a user written ["UPDATE_PASSWORD","UPDATE_PROFILE"] and one written
// ["UPDATE_PROFILE","UPDATE_PASSWORD"] were both served UPDATE_PROFILE first,
// which is priority 40 against 57. The array order is not even preserved by the
// admin API, which stored both writes the same way round - so an implementation
// reading the array in order would be reading something Keycloak does not keep.
//
// RequiredActionRepo.ListByRealm already returns priority order, which is why
// nothing is sorted here.
//
// It returns "" when the login may go on to the consent, and it is a store read
// on every authenticated request - so it returns early for the overwhelmingly
// common user who carries nothing at all.
func (h *handler) nextRequiredAction(ctx context.Context, realm *model.Realm, user *model.User) (string, error) {
	if len(user.RequiredActions) == 0 {
		return "", nil
	}
	providers, err := h.store.RequiredActions().ListByRealm(ctx, realm.ID)
	if err != nil {
		return "", err
	}
	for _, provider := range providers {
		if !provider.Enabled || !slices.Contains(user.RequiredActions, provider.Alias) {
			continue
		}
		if provider.Alias == verifyEmailAction {
			if !user.EmailVerified {
				return verifyEmailAction, nil
			}
			if err := h.clearRequiredAction(ctx, user, verifyEmailAction); err != nil {
				return "", err
			}
			continue
		}
		switch requiredActionTable[provider.Alias].kind {
		case actionForm, actionPlaceholder:
			return provider.Alias, nil
		case actionSelfClears:
			if err := h.clearRequiredAction(ctx, user, provider.Alias); err != nil {
				return "", err
			}
		}
	}
	return "", nil
}

// clearRequiredAction removes one alias from the user and writes it back.
//
// **The clear happens per action, at the moment that action succeeds, not at the
// end of the login.** Measured on a user carrying UPDATE_PROFILE and
// UPDATE_PASSWORD: after the profile form was submitted and while the password
// page was still on screen, the admin representation already read
// ["UPDATE_PASSWORD"] and the new first and last names were already stored. A
// handler that wrote the whole list back when the login finished would leave an
// abandoned login's completed action undone.
//
// It mutates the in-memory user too, so the caller can go on asking the queue
// without re-reading the row.
func (h *handler) clearRequiredAction(ctx context.Context, user *model.User, alias string) error {
	remaining := make([]string, 0, len(user.RequiredActions))
	for _, a := range user.RequiredActions {
		if a != alias {
			remaining = append(remaining, a)
		}
	}
	updated := *user
	updated.RequiredActions = remaining
	if err := h.store.Users().Update(ctx, &updated); err != nil {
		return err
	}
	user.RequiredActions = remaining
	return nil
}

// tabStep is what /login-actions/required-action is currently for on this tab:
// the queue's head, then OAUTH_GRANT, then nothing.
//
// **The required actions come before the consent**, which is measured rather
// than assumed: a consentRequired client with a user carrying UPDATE_PASSWORD
// redirected to execution=UPDATE_PASSWORD, and completing it answered 200 with
// the consent page rather than a code. So the consent is the last member of one
// queue and not a stage beside it, which is why one function answers both and
// one endpoint serves both.
func (h *handler) tabStep(ctx context.Context, realm *model.Realm, client *model.Client,
	user *model.User, tab *authTab) (string, error) {
	alias, err := h.nextRequiredAction(ctx, realm, user)
	if err != nil {
		return "", err
	}
	if alias != "" {
		return alias, nil
	}
	if h.tabConsentNeeded(realm, client, user, tab) {
		return executionOAuthGrant, nil
	}
	return "", nil
}

// serveStep renders whatever page the tab's current step calls for.
//
// The three kinds it can be asked for are the consent page, a required action
// with a real form, and a required action Gloak can only put an envelope under.
// message is the feedback line a re-served page carries and is empty on a first
// render.
func (h *handler) serveStep(w http.ResponseWriter, realm *model.Realm, sess *authSession,
	tab *authTab, client *model.Client, user *model.User, step, message string) {
	if step == executionOAuthGrant {
		h.serveConsentPage(w, realm, sess, tab, client)
		return
	}
	if step == verifyEmailAction {
		// Measured: with emailVerified false and no SMTP configured, the landing
		// is 500 with the theme error page and "Failed to send email, please try
		// again later.". A default start-dev container configures no SMTP and
		// neither does Gloak, so this is the answer for every realm this project
		// can serve - the same standing that CIBA's 503 has, and the same
		// standing writeRegistrationPage's 400 has.
		//
		// Its chrome is writeRegistrationPage's rather than the 400 page's, and
		// that was measured on 2026-09-02 rather than assumed: the restart URL
		// carries client_id, tab_id and client_data, because this page too is
		// rendered from inside the authentication flow. It is what stops this
		// page being comparable in a golden and does not stop it being served.
		httpx.WriteThemeErrorPage(w, http.StatusInternalServerError, loginActionCacheControl,
			h.flowChrome(realm, client, sess, tab), pageVerifyEmailFailed)
		return
	}
	spec := requiredActionTable[step]
	action, err := h.requiredActionURL(realm, sess, tab, step)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	switch step {
	case updatePasswordAction:
		if message == "" {
			message = httpx.UpdatePasswordPrompt
		}
		httpx.WriteThemeUpdatePasswordPage(w, action, message)
	case updateProfileAction:
		if message == "" {
			message = httpx.UpdateProfilePrompt
		}
		httpx.WriteThemeUpdateProfilePage(w, action, user.Email, user.FirstName, user.LastName, message)
	default:
		// A page whose form Gloak cannot serve. The envelope, the status and the
		// heading are measured; the body is the placeholder every other theme
		// page in this project serves, and the login stops here rather than
		// issuing tokens to a user who is not set up.
		httpx.WriteThemePage(w, http.StatusOK, loginActionCacheControl, spec.title)
	}
}

// requiredActionURL is the action a required-action page posts to: this
// endpoint's own path, with the login form's five parameters and the alias in
// execution.
//
// It is **not** the consent page's shape. That one posts to
// /login-actions/consent and carries three parameters with no session_code, and
// the difference is measured on one container minutes apart. Building one URL
// for both is the saving that makes the required action unsubmittable.
func (h *handler) requiredActionURL(realm *model.Realm, sess *authSession, tab *authTab, step string) (string, error) {
	code, err := h.auth.rotateSessionCode(sess, tab, tab.Username)
	if err != nil {
		return "", err
	}
	data, err := tab.clientData()
	if err != nil {
		return "", err
	}
	return h.realmBase(realm.Name) + "/login-actions/required-action?" + strings.Join([]string{
		"session_code=" + url.QueryEscape(code),
		"execution=" + url.QueryEscape(step),
		"client_id=" + url.QueryEscape(tab.ClientID),
		"tab_id=" + url.QueryEscape(tab.TabID),
		"client_data=" + url.QueryEscape(data),
	}, "&"), nil
}

// runStep executes the submitted required action and reports whether the login
// may go on.
//
// A failure re-serves the page with the measured message and rotates the session
// code, exactly as a wrong password does at /login-actions/authenticate.
func (h *handler) runStep(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, sess *authSession, tab *authTab, user *model.User, step string) bool {
	switch step {
	case updatePasswordAction:
		return h.runUpdatePassword(w, r, realm, client, sess, tab, user)
	case updateProfileAction:
		return h.runUpdateProfile(w, r, realm, client, sess, tab, user)
	default:
		// An action Gloak serves an envelope for has no form to submit, so a
		// submission is answered with the page again rather than with an
		// invented refusal.
		h.serveStep(w, realm, sess, tab, client, user, step, "")
		return false
	}
}

// runUpdatePassword is the UPDATE_PASSWORD action.
//
// **Two failures, two sentences.** Measured: an empty password-new answers
// "Please specify password." and a mismatched confirmation answers "Passwords
// don't match." - so the obvious single "invalid password" message is wrong on
// one of the two, and the empty case is checked first, since an empty pair is
// also a matching pair.
func (h *handler) runUpdatePassword(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, sess *authSession, tab *authTab, user *model.User) bool {
	password := r.PostForm.Get("password-new")
	if password == "" {
		h.serveStep(w, realm, sess, tab, client, user, updatePasswordAction, httpx.PasswordMissingMessage)
		return false
	}
	if r.PostForm.Get("password-confirm") != password {
		h.serveStep(w, realm, sess, tab, client, user, updatePasswordAction, httpx.PasswordMismatchMessage)
		return false
	}
	cred, err := h.newPasswordCredential(r.Context(), user, password)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	if err := h.store.Users().SetCredential(r.Context(), cred); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	if err := h.clearRequiredAction(r.Context(), user, updatePasswordAction); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	return true
}

// runUpdateProfile is the UPDATE_PROFILE action: the three fields the measured
// page carries, written straight onto the user.
//
// The username is not among them, which matches the admin API's measured rule
// that a username is immutable on update - so this page cannot be a way round
// it.
func (h *handler) runUpdateProfile(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, sess *authSession, tab *authTab, user *model.User) bool {
	updated := *user
	updated.Email = r.PostForm.Get("email")
	updated.FirstName = r.PostForm.Get("firstName")
	updated.LastName = r.PostForm.Get("lastName")
	if err := h.store.Users().Update(r.Context(), &updated); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	*user = updated
	if err := h.clearRequiredAction(r.Context(), user, updateProfileAction); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	return true
}

// The argon2 parameters a password set through a required action is hashed with.
//
// **They are a third copy**, matching internal/bootstrap's and internal/admin's
// to the digit. Neither of those packages is this cut's to edit, and a shared
// home for them is a follow-up rather than something to invent here. What keeps
// the copies harmless today is that auth.VerifyPassword reads every parameter
// off the credential rather than from a constant, so a credential written by any
// of the three verifies against all of them; what makes the duplication worth
// filing is that nothing fails if one copy drifts.
const (
	argonTime      = 5
	argonMemoryKiB = 7168
	argonThreads   = 1
	argonKeyLength = 32
	saltLength     = 16
)

// newPasswordCredential hashes a new password for an existing user.
//
// It reuses the existing credential's id when there is one, which is the
// measured shape of a password replacement: reset-password was measured
// replacing the credential in place, same id and a refreshed createdDate.
func (h *handler) newPasswordCredential(ctx context.Context, user *model.User, password string) (*model.Credential, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	id := model.NewID()
	if existing, err := h.store.Users().CredentialByUser(ctx, user.ID, passwordCredentialType); err == nil {
		id = existing.ID
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	return &model.Credential{
		ID:             id,
		UserID:         user.ID,
		Type:           passwordCredentialType,
		CreatedDate:    time.Now().UnixMilli(),
		Algorithm:      "argon2",
		HashIterations: argonTime,
		AdditionalParameters: map[string][]string{
			"hashLength":  {strconv.Itoa(argonKeyLength)},
			"memory":      {strconv.Itoa(argonMemoryKiB)},
			"type":        {"id"},
			"version":     {"1.3"},
			"parallelism": {strconv.Itoa(argonThreads)},
		},
		Salt:      salt,
		HashValue: argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLength),
	}, nil
}

// beginRequiredActionFromSSO is what a signed-in browser gets when the flow
// still wants something from it - a required action or a consent.
//
// Measured on both: a browser holding a live KEYCLOAK_IDENTITY whose user gained
// UPDATE_PASSWORD between two GET /auth requests is answered a **302 straight to
// /login-actions/required-action** with no login page in between, exactly as
// prompt=consent on an already-consented client is. So the SSO path and the
// credential path converge on this endpoint rather than only on the consent.
//
// The authentication session is rooted at the **user session's** id for the
// reason completeSSO records: the session_state a completed login reports has to
// be the one the browser already has.
func (h *handler) beginRequiredActionFromSSO(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, k *keys.RealmKeys, sess *browserSession, req *authRequest, step string) {
	tab := req.tab(client)
	tab.UserID = sess.User.ID
	if _, err := h.resumeAuthSession(w, r, realm, k, sess.Session.ID, tab, req.restart(realm, client)); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.writeRequiredActionRedirect(w, realm, client, tab, step)
}

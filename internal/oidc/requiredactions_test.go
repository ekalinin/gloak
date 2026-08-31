package oidc_test

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/auth"
	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// Required actions at login. Every claim here was measured on a live 26.7.1 on
// 2026-08-31, container kc-reqact on 8121; see
// docs/superpowers/plans/2026-08-31-p8-required-actions-at-login.md.
//
// None of it is reachable from a golden: each case is three or four requests
// carrying state in cookies a conformance case masks as volatile, and the store
// writes they cause are only visible through the store.

// setActions puts required actions on master's `admin` and returns the store so
// the test can read them back.
func setActions(t *testing.T, s store.Store, actions ...string) *model.User {
	t.Helper()
	ctx := context.Background()
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	user, err := s.Users().ByUsername(ctx, realm.ID, "admin")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}
	user.RequiredActions = actions
	if err := s.Users().Update(ctx, user); err != nil {
		t.Fatalf("Update: %v", err)
	}
	return user
}

// directGrant runs one password grant for master's `admin` at admin-cli, which
// is the one bootstrapped client with direct access grants enabled.
func directGrant(t *testing.T, h http.Handler, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {"admin"}, "password": {password},
	}
	req := httptest.NewRequest(http.MethodPost,
		"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// storedActions reads the user's list back.
func storedActions(t *testing.T, s store.Store) []string {
	t.Helper()
	ctx := context.Background()
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	user, err := s.Users().ByUsername(ctx, realm.ID, "admin")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}
	return user.RequiredActions
}

// browserAt logs in and returns the required-action landing the login redirects
// to, failing if it redirected anywhere else.
func (b *browser) browserAt(t *testing.T, client string) string {
	t.Helper()
	overrides := map[string]string{}
	if client != "" {
		overrides["client_id"] = client
	}
	action, _ := actionParams(t, b.login(overrides))
	w := b.do(http.MethodPost, action, credentials("admin", "admin"))
	if w.Code != http.StatusFound {
		t.Fatalf("the credentials: want 302, got %d\n%s", w.Code, w.Body)
	}
	location := w.Header().Get("Location")
	if !strings.Contains(location, "/login-actions/required-action?") {
		t.Fatalf("want the required-action redirect, got %s", location)
	}
	return location
}

// TestATemporaryPasswordIsActuallyTemporary is the whole of F104 in one test.
//
// A user carrying UPDATE_PASSWORD gets **no code** from the login: the 302 goes
// to the action, not to the client, and it sets no cookies at all. Completing
// the action answers the ordinary redirect with a code and the three cookies,
// clears the action, and leaves the new password working and the old one not.
func TestATemporaryPasswordIsActuallyTemporary(t *testing.T) {
	h, s := authServerAndStore(t)
	b := &browser{h: h, t: t, jar: map[string]string{}}
	setActions(t, s, "UPDATE_PASSWORD")

	landing := b.browserAt(t, "")
	if !strings.Contains(landing, "execution=UPDATE_PASSWORD") {
		t.Fatalf("want execution=UPDATE_PASSWORD, got %s", landing)
	}
	if len(b.last.Header().Values("Set-Cookie")) != 0 {
		t.Errorf("the redirect to an action sets no cookies, got %v",
			b.last.Header().Values("Set-Cookie"))
	}

	w := b.do(http.MethodGet, landing, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("the landing: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), httpx.UpdatePasswordPageTitle) {
		t.Fatalf("want the %q page, got %s", httpx.UpdatePasswordPageTitle, w.Body)
	}
	form, _ := actionParams(t, formAction(t, w.Body.String()))

	w = b.do(http.MethodPost, form, url.Values{
		"password-new": {"n3w-passw0rd"}, "password-confirm": {"n3w-passw0rd"},
	})
	if w.Code != http.StatusFound {
		t.Fatalf("the completed action: want 302, got %d\n%s", w.Code, w.Body)
	}
	if location := w.Header().Get("Location"); !strings.Contains(location, "code=") {
		t.Errorf("want a code, got %s", location)
	}
	if got := storedActions(t, s); len(got) != 0 {
		t.Errorf("the action should be cleared, got %v", got)
	}

	ctx := context.Background()
	realm, _ := s.Realms().ByName(ctx, "master")
	user, _ := s.Users().ByUsername(ctx, realm.ID, "admin")
	cred, err := s.Users().CredentialByUser(ctx, user.ID, "password")
	if err != nil {
		t.Fatalf("CredentialByUser: %v", err)
	}
	if err := auth.VerifyPassword(cred, "n3w-passw0rd"); err != nil {
		t.Errorf("the new password should verify: %v", err)
	}
	if err := auth.VerifyPassword(cred, "admin"); err == nil {
		t.Error("the old password should not verify any more")
	}
}

// TestRequiredActionsAreServedInPriorityOrder is the claim a test that broke one
// thing at a time would not have pinned.
//
// **Both orderings of the same two aliases give the same page**, because the
// order comes from the provider's priority - UPDATE_PROFILE 40, UPDATE_PASSWORD
// 57 - and not from the user's array. Asserting one ordering alone would pass on
// a handler that read the array in order, which is the obvious implementation.
func TestRequiredActionsAreServedInPriorityOrder(t *testing.T) {
	for _, order := range [][]string{
		{"UPDATE_PASSWORD", "UPDATE_PROFILE"},
		{"UPDATE_PROFILE", "UPDATE_PASSWORD"},
	} {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			h, s := authServerAndStore(t)
			b := &browser{h: h, t: t, jar: map[string]string{}}
			setActions(t, s, order...)
			landing := b.browserAt(t, "")
			if !strings.Contains(landing, "execution=UPDATE_PROFILE") {
				t.Fatalf("want UPDATE_PROFILE first whatever the array order, got %s", landing)
			}
		})
	}
}

// TestASecondActionIsServedInPlace. Measured: submitting the first action
// answers **200 with the next action's page**, not a 302 to it. Only the end of
// the queue redirects.
//
// It also pins the per-action clear: the first alias is gone from the store
// while the second is still on screen, so an abandoned login keeps what it
// finished.
func TestASecondActionIsServedInPlace(t *testing.T) {
	h, s := authServerAndStore(t)
	b := &browser{h: h, t: t, jar: map[string]string{}}
	setActions(t, s, "UPDATE_PROFILE", "UPDATE_PASSWORD")

	landing := b.browserAt(t, "")
	w := b.do(http.MethodGet, landing, nil)
	form, _ := actionParams(t, formAction(t, w.Body.String()))
	w = b.do(http.MethodPost, form, url.Values{
		"email": {"admin@example.org"}, "firstName": {"Given"}, "lastName": {"Family"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("the second action: want 200 in place, got %d %s",
			w.Code, w.Header().Get("Location"))
	}
	if !strings.Contains(w.Body.String(), httpx.UpdatePasswordPageTitle) {
		t.Fatalf("want the %q page, got %s", httpx.UpdatePasswordPageTitle, w.Body)
	}
	if got := storedActions(t, s); len(got) != 1 || got[0] != "UPDATE_PASSWORD" {
		t.Errorf("the finished action should already be cleared, got %v", got)
	}
	ctx := context.Background()
	realm, _ := s.Realms().ByName(ctx, "master")
	user, _ := s.Users().ByUsername(ctx, realm.ID, "admin")
	if user.FirstName != "Given" || user.LastName != "Family" {
		t.Errorf("the profile should already be written, got %q %q", user.FirstName, user.LastName)
	}
}

// TestTheConsentFollowsTheRequiredActions. Measured on a consentRequired client
// whose user carries UPDATE_PASSWORD: the login goes to the action, and
// completing it answers 200 with the consent page. So OAUTH_GRANT is the last
// member of one queue rather than a stage beside it.
func TestTheConsentFollowsTheRequiredActions(t *testing.T) {
	h, s := authServerAndStore(t)
	b := &browser{h: h, t: t, jar: map[string]string{}}
	setActions(t, s, "UPDATE_PASSWORD")

	landing := b.browserAt(t, "probe-consent")
	if !strings.Contains(landing, "execution=UPDATE_PASSWORD") {
		t.Fatalf("the action outranks the consent, got %s", landing)
	}
	w := b.do(http.MethodGet, landing, nil)
	form, _ := actionParams(t, formAction(t, w.Body.String()))
	w = b.do(http.MethodPost, form, url.Values{
		"password-new": {"n3w-passw0rd"}, "password-confirm": {"n3w-passw0rd"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want the consent page in place, got %d %s", w.Code, w.Header().Get("Location"))
	}
	if !strings.Contains(w.Body.String(), "Grant Access to probe-consent") {
		t.Fatalf("want the consent page, got %s", w.Body)
	}
}

// TestADisabledProviderIsSkippedAndLeftOnTheUser.
//
// **The two subtests are not one test written twice, and the first version had
// only the second of them.** Deleting the `!provider.Enabled` clause from
// nextRequiredAction survived a suite that used TERMS_AND_CONDITIONS alone,
// because that alias has no row in requiredActionTable and an absent row reads
// as actionSkipped - so the alias was skipped for the wrong reason and the
// answer never moved. The enabled filter can only be pinned by disabling a
// provider Gloak would otherwise **serve**, which is what the first subtest
// does. A survivor is a finding about the test.
//
// The second subtest is still worth its keep for the other half: `enabled` is
// not a delete, and the alias is measured still on the user after a login that
// skipped it.
func TestADisabledProviderIsSkippedAndLeftOnTheUser(t *testing.T) {
	t.Run("a provider Gloak would otherwise serve", func(t *testing.T) {
		h, s := authServerAndStore(t)
		b := &browser{h: h, t: t, jar: map[string]string{}}
		setActions(t, s, "UPDATE_PASSWORD")
		disableProvider(t, s, "UPDATE_PASSWORD")

		action, _ := actionParams(t, b.login(nil))
		w := b.do(http.MethodPost, action, credentials("admin", "admin"))
		if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "code=") {
			t.Fatalf("a disabled provider should not stop the login, got %d %s",
				w.Code, w.Header().Get("Location"))
		}
		if got := storedActions(t, s); len(got) != 1 || got[0] != "UPDATE_PASSWORD" {
			t.Errorf("a skipped action stays on the user, got %v", got)
		}
	})

	t.Run("TERMS_AND_CONDITIONS, disabled on every default realm", func(t *testing.T) {
		h, s := authServerAndStore(t)
		b := &browser{h: h, t: t, jar: map[string]string{}}
		setActions(t, s, "TERMS_AND_CONDITIONS")

		action, _ := actionParams(t, b.login(nil))
		w := b.do(http.MethodPost, action, credentials("admin", "admin"))
		if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "code=") {
			t.Fatalf("a disabled action should not stop the login, got %d %s",
				w.Code, w.Header().Get("Location"))
		}
		if got := storedActions(t, s); len(got) != 1 || got[0] != "TERMS_AND_CONDITIONS" {
			t.Errorf("a skipped action stays on the user, got %v", got)
		}
	})
}

// disableProvider turns one of master's registered required actions off, the
// way PUT /admin/realms/{realm}/authentication/required-actions/{alias} does.
func disableProvider(t *testing.T, s store.Store, alias string) {
	t.Helper()
	ctx := context.Background()
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	provider, err := s.RequiredActions().ByAlias(ctx, realm.ID, alias)
	if err != nil {
		t.Fatalf("ByAlias %s: %v", alias, err)
	}
	provider.Enabled = false
	if err := s.RequiredActions().Update(ctx, provider); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

// TestAnIncompleteProfileIsNotAnActionInMaster is a measurement about the realm,
// and it is here because the observed document's account of it is wrong.
//
// A user with no email, no first name and no last name is refused
// "Account is not fully set up" **in a realm created through POST /admin/realms**
// and is served a token **in master**. The observed document records that split
// and explains it as "what differs is the user, not the realm: master's
// bootstrapped administrator carries is_temporary_admin". Both halves of that
// explanation were re-measured on 2026-08-31 and both are false:
//
//   - a user in a created realm carrying is_temporary_admin is still refused, so
//     the attribute exempts nothing;
//   - master's own `admin`, attribute and all, is refused the moment master's
//     user-profile configuration is edited to mark the three attributes
//     required.
//
// What differs is the **realm's user profile configuration**:
// GET /admin/realms/{realm}/users/profile carries `"required":{"roles":["user"]}`
// on email, firstName and lastName in a created realm and carries no `required`
// key at all in master.
//
// Gloak bootstraps master and models no user profile, so it serves master's
// answer, and that is what this test pins. Six conformance fixtures create users
// with no profile at all and then log them in; a handler that refused an
// incomplete profile would break every one of them, and would be reproducing a
// created realm's rule in the one realm that does not have it.
func TestAnIncompleteProfileIsNotAnActionInMaster(t *testing.T) {
	h, s := authServerAndStore(t)
	b := &browser{h: h, t: t, jar: map[string]string{}}
	ctx := context.Background()
	realm, _ := s.Realms().ByName(ctx, "master")
	user, _ := s.Users().ByUsername(ctx, realm.ID, "admin")
	user.Email, user.FirstName, user.LastName = "", "", ""
	user.Attributes = map[string][]string{}
	if err := s.Users().Update(ctx, user); err != nil {
		t.Fatalf("Update: %v", err)
	}

	action, _ := actionParams(t, b.login(nil))
	w := b.do(http.MethodPost, action, credentials("admin", "admin"))
	if !strings.Contains(w.Header().Get("Location"), "code=") {
		t.Errorf("browser: want a code, got %s", w.Header().Get("Location"))
	}
	if g := directGrant(t, h, "admin"); g.Code != http.StatusOK {
		t.Errorf("direct grant: want 200, got %d %s", g.Code, g.Body)
	}
}

// TestVerifyProfileClearsItselfAtLogin, where the three skipped aliases do not.
// Measured one at a time: VERIFY_PROFILE came back `[]` after a login that never
// redirected, and idp_link came back still carrying its alias.
func TestVerifyProfileClearsItselfAtLogin(t *testing.T) {
	h, s := authServerAndStore(t)
	b := &browser{h: h, t: t, jar: map[string]string{}}
	setActions(t, s, "VERIFY_PROFILE", "idp_link")

	action, _ := actionParams(t, b.login(nil))
	w := b.do(http.MethodPost, action, credentials("admin", "admin"))
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "code=") {
		t.Fatalf("want a code, got %d %s", w.Code, w.Header().Get("Location"))
	}
	got := storedActions(t, s)
	if len(got) != 1 || got[0] != "idp_link" {
		t.Errorf("VERIFY_PROFILE clears and idp_link stays, got %v", got)
	}
}

// TestTheSessionCodeDecidesNotTheVerb is the six-cell grid, run on both verbs.
//
// The rows were measured as twelve requests and the two verbs agree on all six,
// which is the point: a matrix that varied the verb alone would have concluded
// the verb was the variable, and one that varied the execution alone would have
// missed that a stale session code re-issues the landing rather than expiring.
func TestTheSessionCodeDecidesNotTheVerb(t *testing.T) {
	for _, verb := range []string{http.MethodGet, http.MethodPost} {
		for _, tc := range []struct {
			name       string
			withCode   bool
			execution  string
			wantStatus int
			wantIn     string
		}{
			{"code+match", true, "UPDATE_PASSWORD", http.StatusFound, "code="},
			{"code+mismatch", true, "VERIFY_EMAIL", http.StatusFound, "execution=UPDATE_PASSWORD"},
			{"code+absent", true, "", http.StatusFound, "execution=UPDATE_PASSWORD"},
			{"nocode+match", false, "UPDATE_PASSWORD", http.StatusOK, httpx.UpdatePasswordPageTitle},
			{"nocode+mismatch", false, "VERIFY_EMAIL", http.StatusOK, httpx.ExpiredPageTitle},
			{"nocode+absent", false, "", http.StatusOK, httpx.UpdatePasswordPageTitle},
		} {
			t.Run(verb+"/"+tc.name, func(t *testing.T) {
				h, s := authServerAndStore(t)
				b := &browser{h: h, t: t, jar: map[string]string{}}
				setActions(t, s, "UPDATE_PASSWORD")

				landing := b.browserAt(t, "")
				w := b.do(http.MethodGet, landing, nil)
				form := formAction(t, w.Body.String())

				target := landing
				if tc.withCode {
					target = form
				}
				u, err := url.Parse(target)
				if err != nil {
					t.Fatalf("parse %q: %v", target, err)
				}
				q := u.Query()
				if tc.execution == "" {
					q.Del("execution")
				} else {
					q.Set("execution", tc.execution)
				}
				u.RawQuery = q.Encode()

				var body url.Values
				if verb == http.MethodPost {
					body = url.Values{
						"password-new": {"n3w-passw0rd"}, "password-confirm": {"n3w-passw0rd"},
					}
				}
				w = b.do(verb, u.Path+"?"+u.RawQuery, body)
				// A GET carrying a session code submits with an empty body, so
				// the matching cell answers the page again with the "specify a
				// password" message rather than a code. That is the one place
				// the two verbs differ in outcome and not in rule.
				if verb == http.MethodGet && tc.name == "code+match" {
					if w.Code != http.StatusOK ||
						!strings.Contains(w.Body.String(), httpx.PasswordMissingMessage) {
						t.Fatalf("a GET with a code submits an empty form: got %d %s", w.Code, w.Body)
					}
					return
				}
				if w.Code != tc.wantStatus {
					t.Fatalf("want %d, got %d\n%s", tc.wantStatus, w.Code, w.Body)
				}
				haystack := w.Body.String()
				if w.Code == http.StatusFound {
					haystack = w.Header().Get("Location")
				}
				if !strings.Contains(haystack, tc.wantIn) {
					t.Errorf("want %q in %s", tc.wantIn, haystack)
				}
			})
		}
	}
}

// TestAStaleSessionCodeReIssuesTheLanding. Measured: a submission carrying a
// session code that is not the tab's current one is a 302 back to the landing,
// which is the same answer a mismatched execution gets - not the restart branch
// and not the expired page.
func TestAStaleSessionCodeReIssuesTheLanding(t *testing.T) {
	h, s := authServerAndStore(t)
	b := &browser{h: h, t: t, jar: map[string]string{}}
	setActions(t, s, "UPDATE_PASSWORD")

	landing := b.browserAt(t, "")
	w := b.do(http.MethodGet, landing, nil)
	target, q := actionParams(t, formAction(t, w.Body.String()))
	_ = target
	q.Set("session_code", "not-the-tabs-code")
	w = b.do(http.MethodPost, "/realms/master/login-actions/required-action?"+q.Encode(),
		url.Values{"password-new": {"x"}, "password-confirm": {"x"}})
	if w.Code != http.StatusFound ||
		!strings.Contains(w.Header().Get("Location"), "/login-actions/required-action?execution=UPDATE_PASSWORD") {
		t.Fatalf("want the landing re-issued, got %d %s", w.Code, w.Header().Get("Location"))
	}
}

// TestTheTwoPasswordFailuresAreTwoSentences. Measured: an empty password-new is
// "Please specify password." and a mismatched confirmation is "Passwords don't
// match." - and the empty case is checked first, since an empty pair also
// matches. One message for both would be wrong on one of them.
func TestTheTwoPasswordFailuresAreTwoSentences(t *testing.T) {
	for _, tc := range []struct {
		name       string
		form       url.Values
		wantIn     string
		wantAction bool
	}{
		{"empty", url.Values{"password-new": {""}, "password-confirm": {""}},
			httpx.PasswordMissingMessage, true},
		{"mismatch", url.Values{"password-new": {"a"}, "password-confirm": {"b"}},
			httpx.PasswordMismatchMessage, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, s := authServerAndStore(t)
			b := &browser{h: h, t: t, jar: map[string]string{}}
			setActions(t, s, "UPDATE_PASSWORD")
			landing := b.browserAt(t, "")
			w := b.do(http.MethodGet, landing, nil)
			form, before := actionParams(t, formAction(t, w.Body.String()))

			w = b.do(http.MethodPost, form, tc.form)
			if w.Code != http.StatusOK {
				t.Fatalf("want the page again, got %d", w.Code)
			}
			// The apostrophe in "Passwords don't match." is escaped, and
			// Keycloak's own page escapes it the same way - measured
			// `Passwords don&#39;t match.` in the rendered body.
			if !strings.Contains(w.Body.String(), html.EscapeString(tc.wantIn)) {
				t.Errorf("want %q, got %s", tc.wantIn, w.Body)
			}
			// A failure rotates the session code, the same way a wrong password
			// at /login-actions/authenticate does.
			_, after := actionParams(t, formAction(t, w.Body.String()))
			if before.Get("session_code") == after.Get("session_code") {
				t.Error("a failed action should rotate the session code")
			}
			if got := storedActions(t, s); len(got) != 1 {
				t.Errorf("a failed action clears nothing, got %v", got)
			}
		})
	}
}

// TestAnActionGloakCannotExecuteStopsTheLogin. CONFIGURE_TOTP is measured
// serving a page with a real form, which Gloak cannot reproduce because it does
// not model an otp credential. What it must not do is issue a code.
func TestAnActionGloakCannotExecuteStopsTheLogin(t *testing.T) {
	h, s := authServerAndStore(t)
	b := &browser{h: h, t: t, jar: map[string]string{}}
	setActions(t, s, "CONFIGURE_TOTP")

	landing := b.browserAt(t, "")
	if !strings.Contains(landing, "execution=CONFIGURE_TOTP") {
		t.Fatalf("want execution=CONFIGURE_TOTP, got %s", landing)
	}
	w := b.do(http.MethodGet, landing, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), httpx.ConfigureTOTPPageTitle) {
		t.Fatalf("want the %q page, got %d %s", httpx.ConfigureTOTPPageTitle, w.Code, w.Body)
	}
}

// TestVerifyEmailIsTwoAnswers. Measured: with emailVerified true the landing
// redirects to the client and **clears** the action; with it false the landing
// is 500 with "Failed to send email, please try again later.", because no
// default container - and no Gloak - configures SMTP.
func TestVerifyEmailIsTwoAnswers(t *testing.T) {
	t.Run("verified", func(t *testing.T) {
		h, s := authServerAndStore(t)
		b := &browser{h: h, t: t, jar: map[string]string{}}
		setEmailVerified(t, s, true)
		setActions(t, s, "VERIFY_EMAIL")

		action, _ := actionParams(t, b.login(nil))
		w := b.do(http.MethodPost, action, credentials("admin", "admin"))
		if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "code=") {
			t.Fatalf("want a code, got %d %s", w.Code, w.Header().Get("Location"))
		}
		if got := storedActions(t, s); len(got) != 0 {
			t.Errorf("a satisfied VERIFY_EMAIL clears itself, got %v", got)
		}
	})
	t.Run("unverified", func(t *testing.T) {
		h, s := authServerAndStore(t)
		b := &browser{h: h, t: t, jar: map[string]string{}}
		setEmailVerified(t, s, false)
		setActions(t, s, "VERIFY_EMAIL")

		landing := b.browserAt(t, "")
		w := b.do(http.MethodGet, landing, nil)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("want 500, got %d\n%s", w.Code, w.Body)
		}
		if got := storedActions(t, s); len(got) != 1 {
			t.Errorf("an unreachable VERIFY_EMAIL clears nothing, got %v", got)
		}
	})
}

func setEmailVerified(t *testing.T, s store.Store, verified bool) {
	t.Helper()
	ctx := context.Background()
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	user, err := s.Users().ByUsername(ctx, realm.ID, "admin")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}
	user.EmailVerified = verified
	if err := s.Users().Update(ctx, user); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

// TestSSORedirectsToAPendingAction. Measured: a browser holding a live
// KEYCLOAK_IDENTITY whose user gains UPDATE_PASSWORD between two GET /auth
// requests is 302'd straight to the action with no login page in between.
//
// **The pair is the test.** The first GET /auth after the login answers a code,
// which is what says the redirect is caused by the action rather than by the
// jar.
func TestSSORedirectsToAPendingAction(t *testing.T) {
	h, s := authServerAndStore(t)
	b := &browser{h: h, t: t, jar: map[string]string{}}

	action, _ := actionParams(t, b.login(nil))
	if w := b.do(http.MethodPost, action, credentials("admin", "admin")); w.Code != http.StatusFound {
		t.Fatalf("the login: want 302, got %d", w.Code)
	}
	w := b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+baseQuery(nil), nil)
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "code=") {
		t.Fatalf("the control: SSO should answer a code, got %d %s", w.Code, w.Header().Get("Location"))
	}

	setActions(t, s, "UPDATE_PASSWORD")
	w = b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+baseQuery(nil), nil)
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", w.Code)
	}
	if location := w.Header().Get("Location"); !strings.Contains(location,
		"/login-actions/required-action?execution=UPDATE_PASSWORD") {
		t.Fatalf("want the action redirect, got %s", location)
	}
}

// TestPromptNoneWithAPendingActionIsInteractionRequired. Measured: the same code
// a pending consent gets, and not login_required - the browser *is* signed in.
func TestPromptNoneWithAPendingActionIsInteractionRequired(t *testing.T) {
	h, s := authServerAndStore(t)
	b := &browser{h: h, t: t, jar: map[string]string{}}

	action, _ := actionParams(t, b.login(nil))
	if w := b.do(http.MethodPost, action, credentials("admin", "admin")); w.Code != http.StatusFound {
		t.Fatalf("the login: want 302, got %d", w.Code)
	}
	setActions(t, s, "UPDATE_PASSWORD")
	w := b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+
		baseQuery(map[string]string{"prompt": "none"}), nil)
	location := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.Contains(location, "error=interaction_required") {
		t.Fatalf("want interaction_required, got %d %s", w.Code, location)
	}
	if strings.Contains(location, "login_required") {
		t.Errorf("not login_required: the browser is signed in - %s", location)
	}
}

// TestDirectGrantRefusesAnAccountThatIsNotSetUp, and the three neighbouring
// answers that say where the check sits.
//
// **The enabled filter is not applied here**, which is the finding: a user
// carrying only the *disabled* TERMS_AND_CONDITIONS completes the browser login
// - TestADisabledProviderIsSkippedAndLeftOnTheUser above - and is refused
// tokens. One user, two endpoints, opposite answers, and sharing one predicate
// between them is wrong on seven aliases.
func TestDirectGrantRefusesAnAccountThatIsNotSetUp(t *testing.T) {
	for _, tc := range []struct {
		name     string
		actions  []string
		enabled  bool
		password string
		want     string
	}{
		{"set up", nil, true, "admin", ""},
		{"an action pending", []string{"UPDATE_PASSWORD"}, true, "admin", "Account is not fully set up"},
		{"a disabled provider's action", []string{"TERMS_AND_CONDITIONS"}, true, "admin",
			"Account is not fully set up"},
		{"an action and a wrong password", []string{"UPDATE_PASSWORD"}, true, "wrong",
			"Invalid user credentials"},
		{"disabled", nil, false, "admin", "Account disabled"},
		{"disabled with a wrong password", nil, false, "wrong", "Invalid user credentials"},
		{"disabled and an action", []string{"UPDATE_PASSWORD"}, false, "admin", "Account disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, s := authServerAndStore(t)
			ctx := context.Background()
			realm, _ := s.Realms().ByName(ctx, "master")
			user, _ := s.Users().ByUsername(ctx, realm.ID, "admin")
			user.RequiredActions = tc.actions
			user.Enabled = tc.enabled
			if err := s.Users().Update(ctx, user); err != nil {
				t.Fatalf("Update: %v", err)
			}

			w := directGrant(t, h, tc.password)
			if tc.want == "" {
				if w.Code != http.StatusOK {
					t.Fatalf("want 200, got %d\n%s", w.Code, w.Body)
				}
				return
			}
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d\n%s", w.Code, w.Body)
			}
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Errorf("want %q, got %s", tc.want, w.Body)
			}
		})
	}
}

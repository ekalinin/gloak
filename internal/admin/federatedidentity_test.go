package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
)

// federatedIdentityPath is the listing; the writes hang a provider alias off it.
func federatedIdentityPath(userID string) string {
	return "/admin/realms/master/users/" + userID + "/federated-identity"
}

// TestAFederatedLinkToAnUnregisteredAliasIsStoredAndInvisible is the finding,
// and **no golden can state it**: a golden holds one response, and this is
// three responses about one row - a 204 that stores it, a listing that does not
// show it, and a 409 that proves it is there.
//
// The control is the second half of the test: registering an identity provider
// with that alias, which touches nothing about the link, makes the identical
// listing answer differently. Without it the first half is equally well
// explained by "the write silently dropped the row", which is exactly the
// tidy-up this behaviour invites.
func TestAFederatedLinkToAnUnregisteredAliasIsStoredAndInvisible(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	ctx := context.Background()
	u := createUserWithPassword(t, s, realm, "fi-invisible", "pw")

	body := `{"userId":"ext-1","userName":"name-1"}`
	if w := send(t, h, http.MethodPost, federatedIdentityPath(u.ID)+"/ghost", admin, body); w.Code != http.StatusNoContent {
		t.Fatalf("linking an unregistered alias: %d %s", w.Code, w.Body)
	}

	if got := federatedIdentityAliases(t, h, admin, u.ID); len(got) != 0 {
		t.Errorf("the listing shows an unregistered alias: %v", got)
	}

	// The row is there: a repeat is the measured 409.
	w := send(t, h, http.MethodPost, federatedIdentityPath(u.ID)+"/ghost", admin, body)
	if w.Code != http.StatusConflict {
		t.Fatalf("relinking: %d %s, want 409", w.Code, w.Body)
	}
	if got, want := w.Body.String(), `{"errorMessage":"User is already linked with provider"}`; got != want {
		t.Errorf("409 body:\n got %s\nwant %s", got, want)
	}

	// The control. Nothing about the link changes; the alias becomes real.
	if err := s.IdentityProviders().Create(ctx, &model.IdentityProvider{
		InternalID: model.NewID(), RealmID: realm.ID, Alias: ptr("ghost"), ProviderID: "oidc", Enabled: true,
	}); err != nil {
		t.Fatalf("IdentityProviders().Create: %v", err)
	}
	if got := federatedIdentityAliases(t, h, admin, u.ID); len(got) != 1 || got[0] != "ghost" {
		t.Errorf("after registering the provider the listing is %v, want [ghost]", got)
	}
}

// TestAFederatedLinkTakesItsAliasFromThePathAndNotTheBody pins the half of the
// write a golden cannot separate: the 204 says nothing about which alias was
// stored, and the listing beside it would look the same either way unless the
// body disagrees with the path.
func TestAFederatedLinkTakesItsAliasFromThePathAndNotTheBody(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	ctx := context.Background()
	u := createUserWithPassword(t, s, realm, "fi-path-wins", "pw")
	for _, alias := range []string{"real", "other"} {
		if err := s.IdentityProviders().Create(ctx, &model.IdentityProvider{
			InternalID: model.NewID(), RealmID: realm.ID, Alias: ptr(alias), ProviderID: "oidc", Enabled: true,
		}); err != nil {
			t.Fatalf("IdentityProviders().Create(%s): %v", alias, err)
		}
	}

	if w := send(t, h, http.MethodPost, federatedIdentityPath(u.ID)+"/real", admin,
		`{"identityProvider":"other","userId":"e","userName":"n"}`); w.Code != http.StatusNoContent {
		t.Fatalf("link: %d %s", w.Code, w.Body)
	}
	if got := federatedIdentityAliases(t, h, admin, u.ID); len(got) != 1 || got[0] != "real" {
		t.Errorf("stored alias %v, want [real] - the body said other", got)
	}
}

// TestTheFederatedIdentityListingIsInsertionOrdered is the reason the store
// carries a sequence column. The two aliases are chosen so that neither sorting
// nor reverse sorting produces the measured answer by accident: `zeta` is added
// first and `alpha` second, and the listing must say zeta, alpha.
func TestTheFederatedIdentityListingIsInsertionOrdered(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	ctx := context.Background()
	u := createUserWithPassword(t, s, realm, "fi-order", "pw")
	for _, alias := range []string{"zeta", "alpha"} {
		if err := s.IdentityProviders().Create(ctx, &model.IdentityProvider{
			InternalID: model.NewID(), RealmID: realm.ID, Alias: ptr(alias), ProviderID: "oidc", Enabled: true,
		}); err != nil {
			t.Fatalf("IdentityProviders().Create(%s): %v", alias, err)
		}
		if w := send(t, h, http.MethodPost, federatedIdentityPath(u.ID)+"/"+alias, admin,
			`{"userId":"e-`+alias+`"}`); w.Code != http.StatusNoContent {
			t.Fatalf("link %s: %d %s", alias, w.Code, w.Body)
		}
	}
	got := federatedIdentityAliases(t, h, admin, u.ID)
	if len(got) != 2 || got[0] != "zeta" || got[1] != "alpha" {
		t.Errorf("listing order %v, want [zeta alpha]", got)
	}
}

// TestAFederatedLinkOmitsTheTwoEmptyKeys pins the `{}`-body case: the row is
// stored and reads back as one key, not three empty ones.
func TestAFederatedLinkOmitsTheTwoEmptyKeys(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	ctx := context.Background()
	u := createUserWithPassword(t, s, realm, "fi-empty-body", "pw")
	if err := s.IdentityProviders().Create(ctx, &model.IdentityProvider{
		InternalID: model.NewID(), RealmID: realm.ID, Alias: ptr("bare"), ProviderID: "oidc", Enabled: true,
	}); err != nil {
		t.Fatalf("IdentityProviders().Create: %v", err)
	}

	if w := send(t, h, http.MethodPost, federatedIdentityPath(u.ID)+"/bare", admin, `{}`); w.Code != http.StatusNoContent {
		t.Fatalf("link: %d %s", w.Code, w.Body)
	}
	w := get(t, h, federatedIdentityPath(u.ID), admin)
	if got, want := w.Body.String(), `[{"identityProvider":"bare"}]`; got != want {
		t.Errorf("listing:\n got %s\nwant %s", got, want)
	}
}

// TestAFederatedLinkWithNoBodyIsAFiveHundred reproduces Keycloak's own defect,
// which is the same one an empty body on POST /users has. It is a test rather
// than a golden because the harness sends no request without a body on this
// route.
func TestAFederatedLinkWithNoBodyIsAFiveHundred(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	u := createUserWithPassword(t, s, realm, "fi-no-body", "pw")

	w := send(t, h, http.MethodPost, federatedIdentityPath(u.ID)+"/anything", admin, "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("no body: %d %s, want 500", w.Code, w.Body)
	}
	want := `{"error":"unknown_error","error_description":"For more on this error consult the server log."}`
	if got := w.Body.String(); got != want {
		t.Errorf("body:\n got %s\nwant %s", got, want)
	}
}

// TestTheFederatedIdentityWritesTakeManageUsersAlone is the guard sweep, run
// one role at a time. `view-users` reads and cannot write, which is the split
// the rest of this tag has; `query-users` opens neither and still gets the
// family's 404 for a subject that does not exist, which is guardUserSubject's
// two stages and not something a single role list can express.
func TestTheFederatedIdentityWritesTakeManageUsersAlone(t *testing.T) {
	h, s, realm := newServer(t)
	u := createUserWithPassword(t, s, realm, "fi-guarded", "pw")

	for _, tc := range []struct {
		role                string
		wantRead, wantWrite int
		wantUnknownUserRead int
	}{
		{"view-users", http.StatusOK, http.StatusForbidden, http.StatusNotFound},
		{"manage-users", http.StatusOK, http.StatusNoContent, http.StatusNotFound},
		{"query-users", http.StatusForbidden, http.StatusForbidden, http.StatusNotFound},
		{"view-clients", http.StatusForbidden, http.StatusForbidden, http.StatusForbidden},
		{"manage-realm", http.StatusForbidden, http.StatusForbidden, http.StatusForbidden},
	} {
		token := tokenForRole(t, h, s, realm, tc.role)
		if w := get(t, h, federatedIdentityPath(u.ID), token); w.Code != tc.wantRead {
			t.Errorf("%s read: %d, want %d", tc.role, w.Code, tc.wantRead)
		}
		if w := send(t, h, http.MethodPost, federatedIdentityPath(u.ID)+"/g-"+tc.role, token,
			`{"userId":"x"}`); w.Code != tc.wantWrite {
			t.Errorf("%s write: %d %s, want %d", tc.role, w.Code, w.Body, tc.wantWrite)
		}
		missing := federatedIdentityPath("00000000-0000-0000-0000-000000000000")
		if w := get(t, h, missing, token); w.Code != tc.wantUnknownUserRead {
			t.Errorf("%s read of an unknown user: %d, want %d", tc.role, w.Code, tc.wantUnknownUserRead)
		}
	}
}

// federatedIdentityAliases reads the listing back as the aliases it shows.
func federatedIdentityAliases(t *testing.T, h http.Handler, token, userID string) []string {
	t.Helper()
	w := get(t, h, federatedIdentityPath(userID), token)
	if w.Code != http.StatusOK {
		t.Fatalf("listing: %d %s", w.Code, w.Body)
	}
	var rows []struct {
		IdentityProvider string `json:"identityProvider"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse listing: %v", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.IdentityProvider)
	}
	return out
}

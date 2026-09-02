package admin

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
)

// catalogueDir holds the bodies a live Keycloak 26.7.1 served on 2026-09-02,
// one file per response, byte for byte as they arrived.
//
// **They are a measurement and not a fixture.** The catalogue in
// internal/model was transcribed from these, so a test that only re-read the
// catalogue would compare a table with itself; these files are the other side.
// Each of them was fetched twice, from two separate container starts, and was
// identical both times - which is what makes them a contract rather than a
// snapshot.
const catalogueDir = "testdata/provider-catalogue-26.7.1"

// identityProviderRegistryForTest is the seventeen ids, spelled out here rather
// than exported from internal/model so that a registry entry silently deleted
// there fails this test instead of shrinking its own oracle.
var identityProviderRegistryForTest = []string{
	"kubernetes", "jwt-authorization-grant", "saml", "oauth2", "oidc",
	"keycloak-oidc", "linkedin-openid-connect", "twitter", "github",
	"openshift-v4", "facebook", "google", "gitlab", "microsoft", "bitbucket",
	"paypal", "stackoverflow",
}

// TestProviderCatalogueReproducesEveryMeasuredBody is the whole check on the
// transcription: all seventeen `providers/{id}` bodies and all fifteen
// `mapper-types` bodies, compared as bytes.
//
// A conformance golden covers four of the thirty-two, because a golden costs a
// case and a case costs a fixture. This covers the other twenty-eight, and it is
// the only thing in the tree that would notice a mistyped helpText in
// `microsoft`.
//
// **It goes through the two functions the handlers call, and that is not
// incidental.** An earlier version assembled the bodies itself, and a mutation
// that reversed the mapper-types loop inside the handler survived it: the test
// compared its own assembly with the measurement while the served bytes moved.
// A test that rebuilds what it is checking is checking the rebuild.
func TestProviderCatalogueReproducesEveryMeasuredBody(t *testing.T) {
	for _, id := range identityProviderRegistryForTest {
		body, ok := identityProviderInfoOf(id)
		if !ok {
			t.Errorf("%s: absent from the catalogue", id)
			continue
		}
		compareWithMeasured(t, "prov-"+id+".json", marshalForTest(t, body))
	}

	served := 0
	for _, id := range identityProviderRegistryForTest {
		out, ok := identityProviderMapperTypesOf(id)
		if !ok {
			continue
		}
		served++
		for _, e := range out {
			if _, found := model.IdentityProviderMapperTypeByID(e.ID); !found {
				t.Fatalf("%s offers mapper type %q and the catalogue has no such entry", id, e.ID)
			}
		}
		compareWithMeasured(t, "mt-"+id+".json", marshalForTest(t, out))
	}
	// Counted from the directory rather than written down: two of the
	// seventeen answer this route with a 500 and have no body to compare.
	if want := len(measuredFiles(t, "mt-")); served != want {
		t.Errorf("served %d mapper-type bodies, measured %d", served, want)
	}
}

// TestTheProvidersWithNoMapperTypesAreTheTwoMeasured500s pins the set, and the
// set is the whole claim.
//
// **This replaces a predicate and a branch that a mutation proved dead.**
// `model.IdentityProviderMapperTypesFail` named two provider ids and the serving
// path asked it before falling through to the catalogue; deleting all four lines
// changed no byte of any response, because the two ids it named are exactly the
// two the catalogue has no mapper set for. Two spellings of one condition, one
// of them unreachable. The condition is asserted here instead.
//
// It fails in **both** directions, which is what a set-valued claim needs and
// what a per-id assertion would not give: an id going missing from the catalogue
// grows this set, and an entry arriving for either of these two shrinks it. Two
// ids behind one claim is exactly the shape where a test pins one and lets the
// other rot, so the comparison is over the whole list rather than a membership
// check per id.
//
// The served half - that both really answer the consult-log 500 over HTTP, and
// that a provider beside them answers its map - is
// TestMapperTypesFollowTheProvider, which sends all five requests.
func TestTheProvidersWithNoMapperTypesAreTheTwoMeasured500s(t *testing.T) {
	var absent []string
	for _, id := range identityProviderRegistryForTest {
		if _, ok := model.IdentityProviderMapperTypes(id); !ok {
			absent = append(absent, id)
		}
	}
	want := []string{"linkedin-openid-connect", "openshift-v4"}
	if strings.Join(absent, ",") != strings.Join(want, ",") {
		t.Errorf("providers with no mapper set: got %v, want %v - and every one of "+
			"them is a measured 500 rather than a gap, so this list moving means "+
			"either the catalogue lost an entry or one of the two started answering",
			absent, want)
	}
}

// TestCatalogueValuesAreNotHTMLEscaped is the guard on marshalOrderedValue.
//
// `saml-username-idp-mapper`'s helpText contains `ATTRIBUTE.<NAME>` and the
// mapper-type body is written by a custom MarshalJSON, which is exactly the
// combination that cannot inherit the encoder's SetEscapeHTML(false). The
// comparison above would catch it too; this names the reason so that a failure
// says what broke rather than printing ten kilobytes.
func TestCatalogueValuesAreNotHTMLEscaped(t *testing.T) {
	out, ok := identityProviderMapperTypesOf("saml")
	if !ok {
		t.Fatal("saml has no mapper types")
	}
	body := string(marshalForTest(t, out))
	if !strings.Contains(body, "ATTRIBUTE.<NAME>") {
		t.Error("the angle brackets in saml-username-idp-mapper's helpText did not survive")
	}
	// The six-character spelling encoding/json produces for `<` when HTML
	// escaping is on, written from its parts so that this line cannot be the
	// thing it is testing for.
	escapedLessThan := `\u` + "003c"
	if strings.Contains(body, escapedLessThan) {
		t.Error("a value was HTML-escaped; Keycloak escapes none of < > &")
	}
}

func marshalForTest(t *testing.T, v any) []byte {
	t.Helper()
	// The same two settings internal/httpx writes every response body with: no
	// HTML escaping and no trailing newline.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

func compareWithMeasured(t *testing.T, name string, got []byte) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join(catalogueDir, name))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s: served body differs from the measured one\n got %s\nwant %s", name, got, want)
	}
}

func measuredFiles(t *testing.T, prefix string) []string {
	t.Helper()
	entries, err := os.ReadDir(catalogueDir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

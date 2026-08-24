package admin

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
)

// Two serialisations, measured. A listing carries six keys and a single read
// seven, the seventh being attributes. See the "Roles" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
func TestRoleRepresentationHasTwoShapes(t *testing.T) {
	r := &model.Role{
		ID: "rid", Name: "admin", Description: "${role_admin}", Composite: true,
		Attributes: map[string][]string{"k": {"v"}},
	}

	brief, err := json.Marshal(roleRepresentationOf(r, "realm-uuid", true))
	if err != nil {
		t.Fatalf("marshal brief: %v", err)
	}
	want := `{"id":"rid","name":"admin","description":"${role_admin}","composite":true,"clientRole":false,"containerId":"realm-uuid"}`
	if string(brief) != want {
		t.Fatalf("brief:\nwant %s\ngot  %s", want, brief)
	}

	full, err := json.Marshal(roleRepresentationOf(r, "realm-uuid", false))
	if err != nil {
		t.Fatalf("marshal full: %v", err)
	}
	want = `{"id":"rid","name":"admin","description":"${role_admin}","composite":true,"clientRole":false,"containerId":"realm-uuid","attributes":{"k":["v"]}}`
	if string(full) != want {
		t.Fatalf("full:\nwant %s\ngot  %s", want, full)
	}
}

// A role with no description omits the key rather than sending "". Measured on
// a role created with only a name.
func TestRoleDescriptionIsAbsentWhenUnset(t *testing.T) {
	got, err := json.Marshal(roleRepresentationOf(&model.Role{ID: "rid", Name: "probe"}, "realm-uuid", true))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"id":"rid","name":"probe","composite":false,"clientRole":false,"containerId":"realm-uuid"}`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

// A role with no attributes still sends {} on a full read, because the key is
// present whenever it is asked for. Measured on `admin`, which has none.
func TestRoleAttributesAreEmptyObjectNotNull(t *testing.T) {
	got, err := json.Marshal(roleRepresentationOf(&model.Role{ID: "rid", Name: "probe"}, "c", false))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `"attributes":{}`; !strings.Contains(string(got), want) {
		t.Fatalf("want %s in %s", want, got)
	}
}

// **The default is the brief shape here and the full one on the user
// listing.** Same parameter, two endpoints, opposite defaults - measured on
// both. A shared helper would get one of them wrong.
func TestBriefRolesDefaultsToTrue(t *testing.T) {
	for query, want := range map[string]bool{
		"":                          true,
		"briefRepresentation=true":  true,
		"briefRepresentation=false": false,
		"briefRepresentation=":      true,
	} {
		q, err := url.ParseQuery(query)
		if err != nil {
			t.Fatalf("ParseQuery(%q): %v", query, err)
		}
		if got := briefRoles(q); got != want {
			t.Fatalf("briefRoles(%q): want %v, got %v", query, want, got)
		}
	}
}

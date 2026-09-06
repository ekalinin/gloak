package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

const metadataPath = "/admin/realms/master/users/profile/metadata"

// measuredMasterMetadata is what a live 26.7.1 answered on 2026-09-06 for
// master, byte for byte. 1196 bytes, md5 d96998890507ef0a1b55714721f626c3.
//
// A created realm answers the identical bytes although its **profile** differs
// from master's by three `required` blocks, which is what
// TestTheMetadataIsTheSameOnBothDefaultProfiles asserts and what made this
// endpoint look like a constant for a fortnight.
const measuredMasterMetadata = `{"attributes":[` +
	`{"name":"username","displayName":"${username}","required":true,"readOnly":false,` +
	`"validators":{"username-prohibited-characters":{"ignore.empty.value":true},` +
	`"multivalued":{"max":"1"},"length":{"max":255,"ignore.empty.value":true,"min":3},` +
	`"up-username-not-idn-homograph":{"ignore.empty.value":true}},"multivalued":false},` +
	`{"name":"email","displayName":"${email}","required":false,"readOnly":false,` +
	`"validators":{"multivalued":{"max":"1"},"length":{"max":255,"ignore.empty.value":true},` +
	`"email":{"ignore.empty.value":true}},"multivalued":false},` +
	`{"name":"firstName","displayName":"${firstName}","required":false,"readOnly":false,` +
	`"validators":{"person-name-prohibited-characters":{"ignore.empty.value":true},` +
	`"multivalued":{"max":"1"},"length":{"max":255,"ignore.empty.value":true}},"multivalued":false},` +
	`{"name":"lastName","displayName":"${lastName}","required":false,"readOnly":false,` +
	`"validators":{"person-name-prohibited-characters":{"ignore.empty.value":true},` +
	`"multivalued":{"max":"1"},"length":{"max":255,"ignore.empty.value":true}},"multivalued":false}],` +
	`"groups":[{"name":"user-metadata","displayHeader":"User metadata",` +
	`"displayDescription":"Attributes, which refer to user metadata"}]}`

// TestTheMetadataIsByteExactOnMaster is the whole derivation asserted at once,
// against bytes read off a live server rather than off this package.
//
// It is here as well as in the golden because the golden compares one response
// and this compares the constant a reader can check against the measurement
// recorded beside it.
func TestTheMetadataIsByteExactOnMaster(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	w := get(t, h, metadataPath, admin)
	if w.Code != http.StatusOK {
		t.Fatalf("GET metadata: %d %s", w.Code, w.Body)
	}
	if got := w.Body.String(); got != measuredMasterMetadata {
		t.Errorf("metadata:\n got %s\nwant %s", got, measuredMasterMetadata)
	}
	if got, want := len(w.Body.String()), 1196; got != want {
		t.Errorf("length %d, want the measured %d", got, want)
	}
}

// TestTheMetadataIsTheSameOnBothDefaultProfiles is the fact that made this
// endpoint look like a constant, asserted **with** the fact that refutes that
// reading: the two realms' profiles differ and their metadata does not.
//
// Asserting only the agreement would be a claim about one value. What earns its
// keep is the pair - the profiles differing is the control, and without it a
// handler answering one constant for every realm would pass.
func TestTheMetadataIsTheSameOnBothDefaultProfiles(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	if w := send(t, h, http.MethodPost, "/admin/realms", admin,
		`{"realm":"md-probe","enabled":true}`); w.Code != http.StatusCreated {
		t.Fatalf("create realm: %d %s", w.Code, w.Body)
	}

	masterProfile := get(t, h, userProfilePath, admin).Body.String()
	createdProfile := get(t, h, "/admin/realms/md-probe/users/profile", admin).Body.String()
	if masterProfile == createdProfile {
		t.Fatalf("the two profiles agree, so this test's control is gone")
	}

	masterMeta := get(t, h, metadataPath, admin).Body.String()
	createdMeta := get(t, h, "/admin/realms/md-probe/users/profile/metadata", admin).Body.String()
	if masterMeta != createdMeta {
		t.Errorf("the two metadata bodies differ where they were measured identical:\n%s\n%s",
			masterMeta, createdMeta)
	}
}

// TestTheMetadataIsDerivedAndNotAConstant is the measurement that refutes the
// sentence this file's header used to carry.
//
// The previous cut could not send this request: it wrote that "nothing
// reachable distinguishes the derivation from a constant", which was true of
// the two profiles a default install has and stopped being true when the
// component write became reachable. A third profile moves the answer, and a
// constant cannot move.
func TestTheMetadataIsDerivedAndNotAConstant(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)

	before := get(t, h, metadataPath, admin).Body.String()

	writeUserProfileDocument(t, s, realm.ID, `{"attributes":[`+
		`{"name":"username","permissions":{"view":["admin","user"],"edit":["admin","user"]},`+
		`"validations":{"length":{"min":4,"max":60}}},`+
		`{"name":"email","permissions":{"view":["admin","user"],"edit":["admin","user"]}}],`+
		`"groups":[]}`)

	after := get(t, h, metadataPath, admin).Body.String()
	if after == before {
		t.Fatalf("the metadata did not move when the profile did:\n%s", after)
	}
	// The two bounds the new profile declared, and neither is in the default.
	for _, want := range []string{`"max":60`, `"min":4`} {
		if !strings.Contains(after, want) {
			t.Errorf("%s is not in the derived metadata:\n%s", want, after)
		}
		if strings.Contains(before, want) {
			t.Errorf("%s was already in the default metadata, so it says nothing", want)
		}
	}
}

// TestMetadataCarriesTheGroupAndDropsTheSelector is here because a mutation
// survived without it.
//
// `Group: a.Group` was replaced with the empty string and every test and every
// golden still passed: **no realm a default install has puts an attribute in a
// group**, so the one committed metadata golden cannot see the field, and none
// of the tests above sent an attribute carrying one. The cell was measured -
// `zzcustom` in a group came back with `"group":"user-metadata"` on a live
// 26.7.1 - so this is a measurement that had not been written down rather than
// a question, and the assertion is the fix.
//
// `selector` is asserted in the same test because it is the field beside it
// that goes the **other** way: the profile carries it and the metadata drops
// it. Asserting only the carried one would be satisfied by a render that copied
// everything.
func TestMetadataCarriesTheGroupAndDropsTheSelector(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	perms := `"permissions":{"view":["admin"],"edit":["admin"]}`
	writeUserProfileDocument(t, s, realm.ID, `{"attributes":[`+
		`{"name":"username",`+perms+`},`+
		`{"name":"grouped",`+perms+`,"group":"g1","selector":{"scopes":["profile"]}}],`+
		`"groups":[{"name":"g1","displayHeader":"H"}]}`)

	body := get(t, h, metadataPath, admin).Body.String()
	var out upMetadataProbe
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var grouped *upMetadataProbeAttribute
	for i := range out.Attributes {
		if out.Attributes[i].Name == "grouped" {
			grouped = &out.Attributes[i]
		}
	}
	if grouped == nil {
		t.Fatalf("the attribute is missing:\n%s", body)
	}
	if got, want := grouped.Group, "g1"; got != want {
		t.Errorf("group = %q, want %q:\n%s", got, want, body)
	}
	// The attribute that declares no group carries no `group` key at all,
	// which is what makes the field omitempty rather than empty-string.
	if strings.Contains(body, `"name":"username","displayName":"username","required":true,`+
		`"readOnly":false,"validators":{"multivalued":{"max":"1"}},"group"`) {
		t.Errorf("an attribute with no group gained the key:\n%s", body)
	}
	if strings.Contains(body, `"selector"`) {
		t.Errorf("selector reached the metadata; it was measured dropped:\n%s", body)
	}
	// And the group really is declared, so the profile's own `groups` array is
	// the control that says this is a copy and not an invention.
	if !strings.Contains(body, `"groups":[{"name":"g1","displayHeader":"H"}]`) {
		t.Errorf("the groups array is not the profile's:\n%s", body)
	}
}

// TestMetadataRequiredIsUsernameAlwaysAndAdminOtherwise pins the rule that took
// seven requests, because three readings fit fewer than seven.
//
// The rows that separate the readings are the last three: `{"roles":[]}` is
// true where "an empty list means nobody" would say false, `{"scopes":[...]}`
// is false where "no roles means everybody" would say true, and `username`
// carrying the same block that makes `email` false is still true.
func TestMetadataRequiredIsUsernameAlwaysAndAdminOtherwise(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required string
		want     bool
	}{
		{"absent", "", false},
		{"empty object", `,"required":{}`, true},
		{"roles admin", `,"required":{"roles":["admin"]}`, true},
		{"roles user", `,"required":{"roles":["user"]}`, false},
		{"roles user and admin", `,"required":{"roles":["user","admin"]}`, true},
		{"roles empty list", `,"required":{"roles":[]}`, true},
		{"scopes only", `,"required":{"scopes":["profile"]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, s, realm := newServer(t)
			admin := adminToken(t, h)
			perms := `"permissions":{"view":["admin","user"],"edit":["admin","user"]}`
			writeUserProfileDocument(t, s, realm.ID, `{"attributes":[`+
				`{"name":"username",`+perms+tc.required+`},`+
				`{"name":"zz",`+perms+tc.required+`}],"groups":[]}`)

			var out upMetadataProbe
			if err := json.Unmarshal(get(t, h, metadataPath, admin).Body.Bytes(), &out); err != nil {
				t.Fatalf("parse: %v", err)
			}
			byName := map[string]upMetadataProbeAttribute{}
			for _, a := range out.Attributes {
				byName[a.Name] = a
			}
			if got := byName["zz"].Required; got != tc.want {
				t.Errorf("zz required = %v, want %v", got, tc.want)
			}
			// username is the control on every row: the identical block that
			// decides zz never decides username.
			if got := byName["username"].Required; !got {
				t.Errorf("username required = false with %q; it was measured true on every input", tc.required)
			}
		})
	}
}

// TestMetadataReadOnlyFollowsTheEditPermission and the drop rule beside it.
//
// `view` deciding whether the attribute exists at all and `edit` deciding
// readOnly are two rules over one field, and a body naming neither separates
// them from "permissions is required".
func TestMetadataReadOnlyAndVisibilityFollowThePermissions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		permissions string
		present     bool
		readOnly    bool
	}{
		{"admin views and edits", `"permissions":{"view":["admin"],"edit":["admin"]}`, true, false},
		{"admin views, user edits", `"permissions":{"view":["admin"],"edit":["user"]}`, true, true},
		{"admin views, nobody edits", `"permissions":{"view":["admin"],"edit":[]}`, true, true},
		{"admin views, edit absent", `"permissions":{"view":["admin","user"]}`, true, true},
		{"user views only", `"permissions":{"view":["user"],"edit":["user"]}`, false, false},
		{"permissions empty", `"permissions":{}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, s, realm := newServer(t)
			admin := adminToken(t, h)
			writeUserProfileDocument(t, s, realm.ID, `{"attributes":[`+
				`{"name":"username","permissions":{"view":["admin"],"edit":["admin"]}},`+
				`{"name":"zz",`+tc.permissions+`}],"groups":[]}`)

			var out upMetadataProbe
			if err := json.Unmarshal(get(t, h, metadataPath, admin).Body.Bytes(), &out); err != nil {
				t.Fatalf("parse: %v", err)
			}
			var zz *upMetadataProbeAttribute
			for i := range out.Attributes {
				if out.Attributes[i].Name == "zz" {
					zz = &out.Attributes[i]
				}
			}
			if tc.present != (zz != nil) {
				t.Fatalf("zz present = %v, want %v", zz != nil, tc.present)
			}
			// username is the control: it is rendered on every row, so a
			// handler dropping everything would fail here rather than pass the
			// two rows that expect a drop.
			if len(out.Attributes) == 0 {
				t.Fatalf("no attributes at all; the control is gone")
			}
			if zz != nil && zz.ReadOnly != tc.readOnly {
				t.Errorf("zz readOnly = %v, want %v", zz.ReadOnly, tc.readOnly)
			}
		})
	}
}

// TestTheMultivaluedValidatorIsSynthesisedForSingleValuedAttributesOnly.
//
// The multivalued attribute is the control, and it is the row that says the
// synthesis is conditional rather than the bound being different: it comes back
// with **no** multivalued validator at all rather than one carrying another max.
func TestTheMultivaluedValidatorIsSynthesisedForSingleValuedAttributesOnly(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	perms := `"permissions":{"view":["admin"],"edit":["admin"]}`
	writeUserProfileDocument(t, s, realm.ID, `{"attributes":[`+
		`{"name":"username",`+perms+`},`+
		`{"name":"single",`+perms+`,"multivalued":false},`+
		`{"name":"many",`+perms+`,"multivalued":true}],"groups":[]}`)

	body := get(t, h, metadataPath, admin).Body.String()
	var out upMetadataProbe
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, a := range out.Attributes {
		_, has := a.Validators["multivalued"]
		switch a.Name {
		case "many":
			if has {
				t.Errorf("a multivalued attribute carries the synthesised validator:\n%s", body)
			}
			if len(a.Validators) != 0 {
				t.Errorf("many's validators = %v, want the empty object", a.Validators)
			}
		default:
			if !has {
				t.Errorf("%s has no multivalued validator:\n%s", a.Name, body)
			}
		}
	}
	// The bound is a JSON **string**, where a declared length's max is a number.
	if !strings.Contains(body, `"multivalued":{"max":"1"}`) {
		t.Errorf("the synthesised bound is not the measured string:\n%s", body)
	}
}

// TestEveryDeclaredValidatorGainsIgnoreEmptyValue, and the synthesised one does
// not - which is the pair, not two claims.
func TestOnlyDeclaredValidatorsGainIgnoreEmptyValue(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	perms := `"permissions":{"view":["admin"],"edit":["admin"]}`
	writeUserProfileDocument(t, s, realm.ID, `{"attributes":[`+
		`{"name":"username",`+perms+`,"validations":{"email":{},"length":{"max":9}}}],"groups":[]}`)

	body := get(t, h, metadataPath, admin).Body.String()
	for _, want := range []string{
		`"email":{"ignore.empty.value":true}`,
		`"length":{"max":9,"ignore.empty.value":true}`,
		`"multivalued":{"max":"1"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s missing:\n%s", want, body)
		}
	}
	if strings.Contains(body, `"multivalued":{"max":"1","ignore.empty.value":true}`) {
		t.Errorf("the synthesised validator gained ignore.empty.value:\n%s", body)
	}
}

// TestMetadataValidatorKeyOrderIsTwoJavaMaps is the key-order claim, and it is
// two claims rather than one: the outer object and the inner one are placed by
// **different** javamap constructors.
//
// Every vector is a body read off a live 26.7.1 on 2026-09-06. The inner rows
// are what says builtFor is the stored count and not the served one: sizing
// `{min, max, ignore.empty.value}` at three puts ignore.empty.value first,
// where the server puts max first.
func TestMetadataValidatorKeyOrderIsTwoJavaMaps(t *testing.T) {
	for _, tc := range []struct {
		name        string
		validations string
		multivalued bool
		want        string
	}{
		{
			name: "master username, four validators",
			validations: `{"length":{"min":3,"max":255},"username-prohibited-characters":{},` +
				`"up-username-not-idn-homograph":{}}`,
			want: `{"username-prohibited-characters":{"ignore.empty.value":true},` +
				`"multivalued":{"max":"1"},"length":{"max":255,"ignore.empty.value":true,"min":3},` +
				`"up-username-not-idn-homograph":{"ignore.empty.value":true}}`,
		},
		{
			name:        "master email, three validators",
			validations: `{"email":{},"length":{"max":255}}`,
			want: `{"multivalued":{"max":"1"},"length":{"max":255,"ignore.empty.value":true},` +
				`"email":{"ignore.empty.value":true}}`,
		},
		{
			name:        "master firstName, three validators",
			validations: `{"length":{"max":255},"person-name-prohibited-characters":{}}`,
			want: `{"person-name-prohibited-characters":{"ignore.empty.value":true},` +
				`"multivalued":{"max":"1"},"length":{"max":255,"ignore.empty.value":true}}`,
		},
		{
			name:        "no validations at all",
			validations: ``,
			want:        `{"multivalued":{"max":"1"}}`,
		},
		{
			name:        "a multivalued attribute with one validator",
			validations: `{"length":{"max":9}}`,
			multivalued: true,
			want:        `{"length":{"max":9,"ignore.empty.value":true}}`,
		},
		{
			name:        "a two-key validator config",
			validations: `{"pattern":{"pattern":"a.*","error-message":"nope"}}`,
			multivalued: true,
			want:        `{"pattern":{"pattern":"a.*","error-message":"nope","ignore.empty.value":true}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, s, realm := newServer(t)
			admin := adminToken(t, h)
			attr := `{"name":"zz","permissions":{"view":["admin"],"edit":["admin"]}`
			if tc.validations != "" {
				attr += `,"validations":` + tc.validations
			}
			if tc.multivalued {
				attr += `,"multivalued":true`
			}
			attr += `}`
			writeUserProfileDocument(t, s, realm.ID, `{"attributes":[`+attr+`],"groups":[]}`)

			body := get(t, h, metadataPath, admin).Body.String()
			if !strings.Contains(body, `"validators":`+tc.want) {
				t.Errorf("validators:\n got %s\nwant %s", body, tc.want)
			}
		})
	}
}

// TestTheSixValidatorKeySetIsTheKnownMiss records the one measured key set
// javamap.KeyOrder does not place, so the gap is a failing expectation nobody
// can mistake for a passing one.
//
// It is **not** a mask. The value is exactly determined and merely unmodelled -
// `pattern` and `options` share a bucket and chain in insertion order, which is
// the limit javamap's own package comment states - and no realm a default
// install can produce reaches it, because it needs five validators declared on
// one attribute.
func TestTheSixValidatorKeySetIsTheKnownMiss(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	writeUserProfileDocument(t, s, realm.ID, `{"attributes":[`+
		`{"name":"zz","permissions":{"view":["admin"],"edit":["admin"]},`+
		`"validations":{"length":{"max":5},"email":{},"uri":{},"pattern":{"pattern":"x"},`+
		`"options":{"options":["a"]}}}],"groups":[]}`)

	body := get(t, h, metadataPath, admin).Body.String()
	var out upMetadataProbe
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The membership is right on all six, which is what makes this a chaining
	// gap rather than a wrong table.
	for _, name := range []string{"multivalued", "length", "pattern", "options", "uri", "email"} {
		if _, ok := out.Attributes[0].Validators[name]; !ok {
			t.Errorf("%s missing from the six:\n%s", name, body)
		}
	}
	const measured = `"multivalued":{"max":"1"},"length":`
	if !strings.Contains(body, measured) {
		t.Errorf("even the placed prefix moved:\n%s", body)
	}
	// The measured server order is pattern before options; javamap.KeyOrder
	// puts options first. Recording which way round Gloak comes out is what
	// makes a later fix visible in a diff rather than silent.
	if !strings.Contains(body, `"options":{"options":["a"],"ignore.empty.value":true},`+
		`"pattern":{"pattern":"x","ignore.empty.value":true}`) {
		t.Errorf("the known miss has changed shape; re-measure before editing this test:\n%s", body)
	}
}

// TestTheMetadataTakesTheSameFiveRolesAsTheProfileRead sweeps both endpoints in
// one loop, so the assertion is that they **agree** rather than that each has
// some list. A handler given its own copy of the five would pass a test that
// checked one; only comparing the pair catches a copy that drifts.
func TestTheMetadataTakesTheSameFiveRolesAsTheProfileRead(t *testing.T) {
	h, s, realm := newServer(t)

	for _, tc := range []struct {
		role string
		want int
	}{
		{"view-users", http.StatusOK},
		{"manage-users", http.StatusOK},
		{"query-users", http.StatusOK},
		{"view-realm", http.StatusOK},
		{"manage-realm", http.StatusOK},
		{"view-clients", http.StatusForbidden},
		{"manage-clients", http.StatusForbidden},
		{"query-clients", http.StatusForbidden},
		{"view-identity-providers", http.StatusForbidden},
		{"view-events", http.StatusForbidden},
		{"impersonation", http.StatusForbidden},
	} {
		token := tokenForRole(t, h, s, realm, tc.role)
		meta := get(t, h, metadataPath, token).Code
		read := get(t, h, userProfilePath, token).Code
		if meta != tc.want {
			t.Errorf("%s on metadata: %d, want %d", tc.role, meta, tc.want)
		}
		if meta != read {
			t.Errorf("%s: metadata %d and the profile read %d; they were measured agreeing",
				tc.role, meta, read)
		}
	}
}

// TestTheMetadataCarriesNoCacheControl - the same pair the read beside it has,
// with the same control one route away.
func TestTheMetadataCarriesNoCacheControl(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	w := get(t, h, metadataPath, admin)
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control: %q, want none", got)
	}
	if got, want := w.Header().Get("Content-Type"), "application/json;charset=UTF-8"; got != want {
		t.Errorf("Content-Type: %q, want %q", got, want)
	}
	u := get(t, h, "/admin/realms/master/credential-registrators", admin)
	if got, want := u.Header().Get("Cache-Control"), "no-cache"; got != want {
		t.Errorf("credential-registrators Cache-Control: %q, want %q", got, want)
	}
}

// upMetadataProbe is a reading shape for the tests above. It is deliberately
// not upMetadata: parsing the response with the type that produced it would
// make a field-name change invisible.
type upMetadataProbe struct {
	Attributes []upMetadataProbeAttribute `json:"attributes"`
	Groups     []map[string]any           `json:"groups"`
}

type upMetadataProbeAttribute struct {
	Name        string                    `json:"name"`
	DisplayName string                    `json:"displayName"`
	Required    bool                      `json:"required"`
	ReadOnly    bool                      `json:"readOnly"`
	Validators  map[string]map[string]any `json:"validators"`
	Group       string                    `json:"group"`
	Multivalued bool                      `json:"multivalued"`
}

// writeUserProfileDocument stores a profile straight into the realm's component,
// bypassing the validators, so a test can reach a document the API would refuse
// and so the read is measured on its own rather than through the write.
func writeUserProfileDocument(t *testing.T, s store.Store, realmID, document string) {
	t.Helper()
	ctx := context.Background()
	components, err := s.Components().List(ctx, realmID)
	if err != nil {
		t.Fatalf("Components().List: %v", err)
	}
	for _, c := range components {
		if c.ProviderType != userProfileComponentType {
			continue
		}
		c.Config = []model.ComponentConfigEntry{{
			Name:   userProfileConfigKey,
			Values: []string{document},
		}}
		if err := s.Components().Update(ctx, c); err != nil {
			t.Fatalf("Components().Update: %v", err)
		}
		return
	}
	t.Fatalf("no %s component in realm %s", userProfileComponentType, realmID)
}

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

// profileWritePath addresses a realm the tests create. **Nothing here writes
// master's profile**: `{}` on master is the body that breaks every login in the
// realm, and a bodyless PUT on master is a second way to the same place - it
// installs the built-in default, whose three `required` blocks the bootstrap
// administrator cannot satisfy. Both cost a container while this cut was being
// measured, the second one after the first had been carefully avoided.
const profileWriteRealm = "up-write"
const profileWritePath = "/admin/realms/" + profileWriteRealm + "/users/profile"

const writePerms = `"permissions":{"view":["admin","user"],"edit":["admin","user"]}`

func profileWriteCore() string {
	var parts []string
	for _, n := range []string{"username", "email", "firstName", "lastName"} {
		parts = append(parts, `{"name":"`+n+`",`+writePerms+`}`)
	}
	return strings.Join(parts, ",")
}

// newProfileWriteRealm returns a handler and an admin token with a realm of its
// own already created.
func newProfileWriteRealm(t *testing.T) (http.Handler, store.Store, string) {
	t.Helper()
	h, s, _ := newServer(t)
	admin := adminToken(t, h)
	if w := send(t, h, http.MethodPost, "/admin/realms", admin,
		`{"realm":"`+profileWriteRealm+`","enabled":true}`); w.Code != http.StatusCreated {
		t.Fatalf("create realm: %d %s", w.Code, w.Body)
	}
	return h, s, admin
}

// TestThePutUserProfileRoundTripsWithTheReadAndTheStore is the measurement that
// decides the handler's shape: **one rendering, answered and stored**, rather
// than an answer built by reading back the write.
//
// Measured all three ways round on one realm: the PUT's body, the GET's body
// and the component's stored config are the same bytes. A handler that answered
// a read of its own write would pass the first comparison and could still store
// something else, which is what `POST .../authz/resource-server/scope` was
// measured doing on a neighbouring family.
func TestThePutUserProfileRoundTripsWithTheReadAndTheStore(t *testing.T) {
	h, s, admin := newProfileWriteRealm(t)

	body := `{"groups":[{"displayDescription":"d","displayHeader":"h","name":"g1"}],` +
		`"attributes":[{"name":"username",` +
		`"permissions":{"edit":["admin","user"],"view":["admin","user"]},` +
		`"validations":{"up-username-not-idn-homograph":{},"length":{"max":255,"min":3}}},` +
		`{"name":"email","permissions":{"edit":["admin"],"view":["admin","user"]},` +
		`"required":{"roles":["user"]},"group":"g1"}]}`

	w := send(t, h, http.MethodPut, profileWritePath, admin, body)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT profile: %d %s", w.Code, w.Body)
	}
	answered := w.Body.String()

	if got := get(t, h, profileWritePath, admin).Body.String(); got != answered {
		t.Errorf("the read disagrees with the write:\n put %s\n get %s", answered, got)
	}
	if got := storedUserProfile(t, s, h, admin); got != answered {
		t.Errorf("the store disagrees with the write:\n put %s\nstore %s", answered, got)
	}
	// The canonicalisation really ran: the request put `groups` first and named
	// no `multivalued`, and the answer does neither.
	if !strings.HasPrefix(answered, `{"attributes":[`) {
		t.Errorf("groups was not moved after attributes:\n%s", answered)
	}
	if !strings.Contains(answered, `"multivalued":false`) {
		t.Errorf("multivalued was not filled in:\n%s", answered)
	}
	if answered == body {
		t.Errorf("the request was echoed; it was measured being rewritten")
	}
}

// TestThePutUserProfileSendsNoCharsetAndTheReadDoes is the header pair, and the
// two are asserted together because that is the whole claim: **three writers on
// two routes of one path.**
//
// This 200 is the third Admin API 2xx body outside the charset rule, after
// `POST /groups/{id}/children`'s 201 and `POST /partial-export`.
func TestThePutUserProfileSendsNoCharsetAndTheReadDoes(t *testing.T) {
	h, _, admin := newProfileWriteRealm(t)

	w := send(t, h, http.MethodPut, profileWritePath, admin,
		`{"attributes":[`+profileWriteCore()+`],"groups":[]}`)
	if got, want := w.Header().Get("Content-Type"), "application/json"; got != want {
		t.Errorf("PUT Content-Type: %q, want %q", got, want)
	}
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Errorf("PUT Cache-Control: %q, want none", got)
	}
	r := get(t, h, profileWritePath, admin)
	if got, want := r.Header().Get("Content-Type"), "application/json;charset=UTF-8"; got != want {
		t.Errorf("GET Content-Type: %q, want %q", got, want)
	}
}

// TestAProfilePutWithNoBodyDeletesTheRow is the reset, with the control that
// makes it a measurement rather than an observation: a marker attribute is
// written, read back, and gone afterwards.
//
// The row really is deleted rather than rewritten with the default, which is
// what the component listing says and what makes the fallback in
// userProfileConfig the whole implementation.
func TestAProfilePutWithNoBodyDeletesTheRow(t *testing.T) {
	for _, body := range []string{"", "null", "  \n "} {
		t.Run("body="+strings.TrimSpace(body), func(t *testing.T) {
			h, s, admin := newProfileWriteRealm(t)

			if w := send(t, h, http.MethodPut, profileWritePath, admin,
				`{"attributes":[`+profileWriteCore()+
					`,{"name":"marker",`+writePerms+`}],"groups":[]}`); w.Code != http.StatusOK {
				t.Fatalf("seed: %d %s", w.Code, w.Body)
			}
			if !strings.Contains(get(t, h, profileWritePath, admin).Body.String(), `"marker"`) {
				t.Fatalf("the marker was not stored, so this test's control is gone")
			}

			w := send(t, h, http.MethodPut, profileWritePath, admin, body)
			if w.Code != http.StatusOK {
				t.Fatalf("reset: %d %s", w.Code, w.Body)
			}
			after := get(t, h, profileWritePath, admin).Body.String()
			if strings.Contains(after, `"marker"`) {
				t.Errorf("the marker survived the reset:\n%s", after)
			}
			if after != defaultUserProfile {
				t.Errorf("the realm does not answer the built-in default:\n%s", after)
			}
			if n := countUserProfileComponents(t, s, h, admin); n != 0 {
				t.Errorf("%d profile components survive the reset, want 0", n)
			}
			// And it is idempotent: a second one on a realm with no row at all.
			if w := send(t, h, http.MethodPut, profileWritePath, admin, body); w.Code != http.StatusOK {
				t.Errorf("second reset: %d %s", w.Code, w.Body)
			}
		})
	}
}

// TestAProfilePutWithAnEmptyObjectIsNotTheReset is the body next door, and it
// is a different outcome: `{}` **stores** a document with no attributes, where
// no body deletes the row. Two bodies a reader would expect to agree, measured
// disagreeing.
func TestAProfilePutWithAnEmptyObjectIsNotTheReset(t *testing.T) {
	h, s, admin := newProfileWriteRealm(t)

	w := send(t, h, http.MethodPut, profileWritePath, admin, `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT {}: %d %s", w.Code, w.Body)
	}
	if got, want := w.Body.String(), `{"groups":[]}`; got != want {
		t.Errorf("PUT {} answered %s, want %s", got, want)
	}
	if got := get(t, h, profileWritePath, admin).Body.String(); got != `{"groups":[]}` {
		t.Errorf("the realm reads back %s, want the stored empty document", got)
	}
	if n := countUserProfileComponents(t, s, h, admin); n != 1 {
		t.Errorf("%d profile components after PUT {}, want the row to exist", n)
	}
}

// TestThePutUserProfileValidators is the nine refusals, every message read off
// a live 26.7.1 on 2026-09-06.
//
// The `attributes: []` row is the one that decides the **list** shape: it earns
// two refusals and they arrive in one body joined with `, `, so a validator
// returning on the first problem would be right on every other row here and
// wrong on the row a caller clearing the profile actually sends.
func TestThePutUserProfileValidators(t *testing.T) {
	core := profileWriteCore()
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			"attributes empty",
			`{"attributes":[],"groups":[]}`,
			`[The attribute 'username' can not be removed, The attribute 'email' can not be removed]`,
		},
		{
			"username removed",
			`{"attributes":[{"name":"email",` + writePerms + `}],"groups":[]}`,
			`[The attribute 'username' can not be removed]`,
		},
		{
			"email removed",
			`{"attributes":[{"name":"username",` + writePerms + `}],"groups":[]}`,
			`[The attribute 'email' can not be removed]`,
		},
		{
			"duplicate name",
			`{"attributes":[` + core + `,{"name":"email",` + writePerms + `}],"groups":[]}`,
			`[Attribute configuration already exists with 'name':'email']`,
		},
		{
			"no name",
			`{"attributes":[` + core + `,{` + writePerms + `}],"groups":[]}`,
			`[Attribute configuration without 'name' is not allowed]`,
		},
		{
			"empty name",
			`{"attributes":[` + core + `,{"name":"",` + writePerms + `}],"groups":[]}`,
			`[Attribute configuration without 'name' is not allowed]`,
		},
		{
			"unknown validator",
			`{"attributes":[` + core + `,{"name":"zz",` + writePerms +
				`,"validations":{"nosuchvalidator":{}}}],"groups":[]}`,
			`[Validator 'nosuchvalidator' defined for attribute 'zz' doesn't exist]`,
		},
		{
			"unsupported view role",
			`{"attributes":[` + core + `,{"name":"zz","permissions":{"view":["nope"],"edit":["admin"]}}],"groups":[]}`,
			`['permissions.view' configuration for attribute 'zz' contains unsupported role 'nope']`,
		},
		{
			"unsupported edit role",
			`{"attributes":[` + core + `,{"name":"zz","permissions":{"view":["admin"],"edit":["nope"]}}],"groups":[]}`,
			`['permissions.edit' configuration for attribute 'zz' contains unsupported role 'nope']`,
		},
		{
			"unknown required scope",
			`{"attributes":[` + core + `,{"name":"zz",` + writePerms +
				`,"required":{"scopes":["nope"]}}],"groups":[]}`,
			`['required.scopes' configuration for attribute 'zz' contains unsupported scope 'nope']`,
		},
		{
			"unknown selector scope",
			`{"attributes":[` + core + `,{"name":"zz",` + writePerms +
				`,"selector":{"scopes":["nope"]}}],"groups":[]}`,
			`['selector.scopes' configuration for attribute 'zz' contains unsupported scope 'nope']`,
		},
		{
			"unknown group",
			`{"attributes":[` + core + `,{"name":"zz",` + writePerms +
				`,"group":"nosuchgroup"}],"groups":[]}`,
			`[Attribute 'zz' references unknown group 'nosuchgroup']`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, admin := newProfileWriteRealm(t)
			w := send(t, h, http.MethodPut, profileWritePath, admin, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400: %s", w.Code, w.Body)
			}
			want := `{"errorMessage":` + quoteJSON(tc.want) + `}`
			if got := w.Body.String(); got != want {
				t.Errorf("\n got %s\nwant %s", got, want)
			}
		})
	}
}

// TestThePutUserProfileAcceptsWhatItShould is the other half of the table, and
// it earns its keep: without it a validator that refused everything would pass
// every row above.
func TestThePutUserProfileAcceptsWhatItShould(t *testing.T) {
	core := profileWriteCore()
	for _, tc := range []struct{ name, body string }{
		{"firstName removed", `{"attributes":[{"name":"username",` + writePerms +
			`},{"name":"email",` + writePerms + `}],"groups":[]}`},
		{"a real required scope", `{"attributes":[` + core + `,{"name":"zz",` + writePerms +
			`,"required":{"scopes":["profile"]}}],"groups":[]}`},
		{"a real selector scope", `{"attributes":[` + core + `,{"name":"zz",` + writePerms +
			`,"selector":{"scopes":["email"]}}],"groups":[]}`},
		{"a declared group", `{"attributes":[` + core + `,{"name":"zz",` + writePerms +
			`,"group":"g1"}],"groups":[{"name":"g1"}]}`},
		{"an unmanagedAttributePolicy", `{"attributes":[` + core +
			`],"groups":[],"unmanagedAttributePolicy":"ENABLED"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, admin := newProfileWriteRealm(t)
			if w := send(t, h, http.MethodPut, profileWritePath, admin, tc.body); w.Code != http.StatusOK {
				t.Errorf("status %d, want 200: %s", w.Code, w.Body)
			}
		})
	}
}

// TestTheValidatorSetIsTheThirtyProvidersAndNotTheCatalogue is the claim
// AGENTS.md's authorization-policy bullet warns about, met on a second family.
//
// `GET /admin/serverinfo` offers two lists seventeen names apart, and the
// endpoint accepts the larger. Validating against the thirteen the component
// catalogue declares would refuse every name in the second group below - all of
// which a live 26.7.1 answered 200.
func TestTheValidatorSetIsTheThirtyProvidersAndNotTheCatalogue(t *testing.T) {
	core := profileWriteCore()
	inBothLists := []string{"double", "email", "integer", "iso-date", "local-date",
		"person-name-prohibited-characters", "up-username-not-idn-homograph", "uri",
		"username-prohibited-characters"}
	// Registered providers the component catalogue does **not** declare.
	inTheThirtyOnly := []string{"not-blank", "not-empty", "organization-member-validator",
		"up-attribute-required-by-metadata-value", "up-blank-attribute-value",
		"up-brokering-federated-username-has-value", "up-duplicate-did", "up-duplicate-email",
		"up-duplicate-username", "up-email-exists-as-username", "up-immutable-attribute",
		"up-readonly-attribute-unchanged", "up-registration-email-as-username-email-value",
		"up-registration-email-as-username-username-value", "up-registration-username-exists",
		"up-username-has-value", "up-username-mutation"}

	h, _, admin := newProfileWriteRealm(t)
	for _, name := range append(append([]string{}, inBothLists...), inTheThirtyOnly...) {
		body := `{"attributes":[` + core + `,{"name":"zz",` + writePerms +
			`,"validations":{"` + name + `":{}}}],"groups":[]}`
		if w := send(t, h, http.MethodPut, profileWritePath, admin, body); w.Code != http.StatusOK {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	// The control: a name outside the thirty is the only one refused for not
	// existing, and it is refused.
	body := `{"attributes":[` + core + `,{"name":"zz",` + writePerms +
		`,"validations":{"nosuchvalidator":{}}}],"groups":[]}`
	if w := send(t, h, http.MethodPut, profileWritePath, admin, body); w.Code != http.StatusBadRequest {
		t.Errorf("an unregistered validator was accepted: %d %s", w.Code, w.Body)
	}
}

// TestFourValidatorsRequireConfiguration is the tenth refusal, and the four are
// a complete sweep rather than a sample: every one of the thirty was sent an
// empty configuration and only these objected.
//
// Two spellings inside it are measured and easy to get wrong by sharing a
// formatter. `length` with neither bound reports **both** hints; and the
// invalid-number error echoes the offending value for `length` and **not** for
// `multivalued`.
func TestFourValidatorsRequireConfiguration(t *testing.T) {
	core := profileWriteCore()
	for _, tc := range []struct{ name, validations, want string }{
		{
			"length with neither bound", `{"length":{}}`,
			`[Validator 'length' defined for attribute 'zz' has incorrect configuration: ` +
				`ValidationError{validatorId='length', inputHint='min', ` +
				`message='error-validator-config-missing-value', messageParameters=[]}, ` +
				`ValidationError{validatorId='length', inputHint='max', ` +
				`message='error-validator-config-missing-value', messageParameters=[]}, ]`,
		},
		{
			"pattern with no pattern", `{"pattern":{}}`,
			`[Validator 'pattern' defined for attribute 'zz' has incorrect configuration: ` +
				`ValidationError{validatorId='pattern', inputHint='pattern', ` +
				`message='error-validator-config-missing-value', messageParameters=[]}, ]`,
		},
		{
			"options with no options", `{"options":{}}`,
			`[Validator 'options' defined for attribute 'zz' has incorrect configuration: ` +
				`ValidationError{validatorId='options', inputHint='options', ` +
				`message='error-validator-config-missing-value', messageParameters=[]}, ]`,
		},
		{
			"multivalued with no max", `{"multivalued":{}}`,
			`[Validator 'multivalued' defined for attribute 'zz' has incorrect configuration: ` +
				`ValidationError{validatorId='multivalued', inputHint='max', ` +
				`message='error-validator-config-missing-value', messageParameters=[]}, ]`,
		},
		{
			"length min is not a number", `{"length":{"min":"x"}}`,
			`[Validator 'length' defined for attribute 'zz' has incorrect configuration: ` +
				`ValidationError{validatorId='length', inputHint='min', ` +
				`message='error-validator-config-invalid-number-value', messageParameters=[x]}, ]`,
		},
		{
			"length min is a boolean", `{"length":{"min":true}}`,
			`[Validator 'length' defined for attribute 'zz' has incorrect configuration: ` +
				`ValidationError{validatorId='length', inputHint='min', ` +
				`message='error-validator-config-invalid-number-value', messageParameters=[true]}, ]`,
		},
		{
			"multivalued max is not a number, and echoes nothing", `{"multivalued":{"max":"x"}}`,
			`[Validator 'multivalued' defined for attribute 'zz' has incorrect configuration: ` +
				`ValidationError{validatorId='multivalued', inputHint='max', ` +
				`message='error-validator-config-invalid-number-value', messageParameters=[]}, ]`,
		},
		{
			"options is not a list", `{"options":{"options":"x"}}`,
			`[Validator 'options' defined for attribute 'zz' has incorrect configuration: ` +
				`ValidationError{validatorId='options', inputHint='options', ` +
				`message='error-validator-config-invalid-value', ` +
				`messageParameters=[must be list of values]}, ]`,
		},
		{
			"pattern is not a string", `{"pattern":{"pattern":1}}`,
			`[Validator 'pattern' defined for attribute 'zz' has incorrect configuration: ` +
				`ValidationError{validatorId='pattern', inputHint='pattern', ` +
				`message='error-validator-config-invalid-value', messageParameters=[1]}, ]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, admin := newProfileWriteRealm(t)
			body := `{"attributes":[` + core + `,{"name":"zz",` + writePerms +
				`,"validations":` + tc.validations + `}],"groups":[]}`
			w := send(t, h, http.MethodPut, profileWritePath, admin, body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400: %s", w.Code, w.Body)
			}
			want := `{"errorMessage":` + quoteJSON(tc.want) + `}`
			if got := w.Body.String(); got != want {
				t.Errorf("\n got %s\nwant %s", got, want)
			}
		})
	}
}

// TestAValidatorConfigThatSatisfiesItsRuleIsAccepted is the other side, and the
// numeric-string row is what says the number check is a parse rather than a
// JSON type test.
func TestAValidatorConfigThatSatisfiesItsRuleIsAccepted(t *testing.T) {
	core := profileWriteCore()
	for _, validations := range []string{
		`{"length":{"min":1}}`,
		`{"length":{"max":9}}`,
		`{"length":{"min":1,"max":9}}`,
		`{"length":{"min":"5"}}`,
		`{"length":{"max":1.5}}`,
		`{"pattern":{"pattern":"a"}}`,
		`{"options":{"options":["a"]}}`,
		`{"multivalued":{"max":3}}`,
		`{"integer":{}}`,
		`{"uri":{}}`,
	} {
		t.Run(validations, func(t *testing.T) {
			h, _, admin := newProfileWriteRealm(t)
			body := `{"attributes":[` + core + `,{"name":"zz",` + writePerms +
				`,"validations":` + validations + `}],"groups":[]}`
			if w := send(t, h, http.MethodPut, profileWritePath, admin, body); w.Code != http.StatusOK {
				t.Errorf("status %d, want 200: %s", w.Code, w.Body)
			}
		})
	}
}

// TestTheProfileStrictDecoderNamesThreeClasses is the sixteenth strict decoder,
// and the only one in this package whose class depends on where the field sits.
//
// **The line and column are absolute in all three**, which is what the last two
// rows say: a field 192 bytes into the document answered column 199 whether it
// was at the top level or inside an attribute. A decoder given the sub-object
// would have reported the fragment's own column and been right only on the
// first attribute of a document with no whitespace.
func TestTheProfileStrictDecoderNamesThreeClasses(t *testing.T) {
	perms := `{"view":["admin","user"],"edit":["admin","user"]}`
	two := `{"name":"username","permissions":` + perms + `},{"name":"email","permissions":` + perms + `}`
	for _, tc := range []struct{ name, body, want string }{
		{"a number at the top", `{"zz":1}`,
			`Invalid json representation for UPConfig. Unrecognized field "zz" at line 1 column 8.`},
		{"a string at the top", `{"zz":"a"}`,
			`Invalid json representation for UPConfig. Unrecognized field "zz" at line 1 column 8.`},
		{"a null at the top", `{"zz":null}`,
			`Invalid json representation for UPConfig. Unrecognized field "zz" at line 1 column 11.`},
		{"after a known field", `{"groups":[],"zz":1}`,
			`Invalid json representation for UPConfig. Unrecognized field "zz" at line 1 column 20.`},
		{"after the attributes array", `{"attributes":[` + two + `],"groups":[],"zz":1}`,
			`Invalid json representation for UPConfig. Unrecognized field "zz" at line 1 column 200.`},
		{"inside the first attribute",
			`{"attributes":[{"name":"username","zz":1,"permissions":` + perms +
				`},{"name":"email","permissions":` + perms + `}],"groups":[]}`,
			`Invalid json representation for UPAttribute. Unrecognized field "zz" at line 1 column 41.`},
		{"inside the third attribute",
			`{"attributes":[` + two + `,{"name":"q","zz":"a","permissions":` + perms + `}],"groups":[]}`,
			`Invalid json representation for UPAttribute. Unrecognized field "zz" at line 1 column 199.`},
		{"inside a group", `{"attributes":[` + two + `],"groups":[{"name":"g","zz":1}]}`,
			`Invalid json representation for UPGroup. Unrecognized field "zz" at line 1 column 210.`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, admin := newProfileWriteRealm(t)
			w := send(t, h, http.MethodPut, profileWritePath, admin, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400: %s", w.Code, w.Body)
			}
			want := `{"error":` + quoteJSON(tc.want) + `}`
			if got := w.Body.String(); got != want {
				t.Errorf("\n got %s\nwant %s", got, want)
			}
		})
	}
}

// TestThePutUserProfileBodyShapes: two parse codes and a 415, and the codes
// follow the body's shape rather than the endpoint - the rule AGENTS.md already
// records, met once more.
func TestThePutUserProfileBodyShapes(t *testing.T) {
	h, _, admin := newProfileWriteRealm(t)

	if got := send(t, h, http.MethodPut, profileWritePath, admin, `{`).Body.String(); got !=
		`{"error":"invalid_request","error_description":"Cannot parse the JSON"}` {
		t.Errorf("a truncated object: %s", got)
	}
	if got := send(t, h, http.MethodPut, profileWritePath, admin, `[]`).Body.String(); got !=
		`{"error":"unknown_error","error_description":"Cannot parse the JSON"}` {
		t.Errorf("an array: %s", got)
	}
	w := sendCT(t, h, http.MethodPut, profileWritePath, admin, "text/plain", "x")
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d %s", w.Code, w.Body)
	}
}

// TestThePutUserProfileGuardIsManageRealmAlone, with the read beside it as the
// control on every row: the write guard is **not** a slice of the read guard's
// five, so a caller that may read this profile and not write it has to exist
// and does.
//
// **It addresses master and not the realm the other tests write.** A caller's
// rights reach exactly one container, so a master caller measured against a
// created realm answers 403 whatever role it holds - which is what the first
// sweep of this guard did, against a live server, and it read 403 in every cell
// and looked like an answer. The realm has to be the caller's own before the
// route's own guard is the thing being measured.
func TestThePutUserProfileGuardIsManageRealmAlone(t *testing.T) {
	h, s, realm := newServer(t)
	body := `{"attributes":[` + profileWriteCore() + `],"groups":[]}`
	const path = "/admin/realms/master/users/profile"

	sawReadOnlyCaller := false
	for _, tc := range []struct {
		role string
		want int
	}{
		{"manage-realm", http.StatusOK},
		{"view-realm", http.StatusForbidden},
		{"view-users", http.StatusForbidden},
		{"manage-users", http.StatusForbidden},
		{"query-users", http.StatusForbidden},
		{"view-clients", http.StatusForbidden},
		{"manage-clients", http.StatusForbidden},
	} {
		token := tokenForRole(t, h, s, realm, tc.role)
		if got := send(t, h, http.MethodPut, path, token, body).Code; got != tc.want {
			t.Errorf("%s on the write: %d, want %d", tc.role, got, tc.want)
		}
		read := get(t, h, path, token).Code
		if read == http.StatusOK && tc.want == http.StatusForbidden {
			sawReadOnlyCaller = true
		}
	}
	if !sawReadOnlyCaller {
		t.Error("no caller reads the profile and cannot write it; the two guards were measured differing")
	}
}

// storedUserProfile reads the document straight out of the realm's component,
// which is what makes the round trip a three-way comparison rather than a
// two-way one.
func storedUserProfile(t *testing.T, s store.Store, h http.Handler, admin string) string {
	t.Helper()
	for _, c := range userProfileComponents(t, s, h, admin) {
		for _, e := range c.Config {
			if e.Name == userProfileConfigKey && len(e.Values) > 0 {
				return e.Values[0]
			}
		}
	}
	t.Fatalf("no stored user profile in %s", profileWriteRealm)
	return ""
}

func countUserProfileComponents(t *testing.T, s store.Store, h http.Handler, admin string) int {
	t.Helper()
	return len(userProfileComponents(t, s, h, admin))
}

func userProfileComponents(t *testing.T, s store.Store, h http.Handler, admin string) []*model.Component {
	t.Helper()
	ctx := context.Background()
	realm, err := s.Realms().ByName(ctx, profileWriteRealm)
	if err != nil {
		t.Fatalf("Realms().ByName: %v", err)
	}
	components, err := s.Components().List(ctx, realm.ID)
	if err != nil {
		t.Fatalf("Components().List: %v", err)
	}
	var out []*model.Component
	for _, c := range components {
		if c.ProviderType == userProfileComponentType {
			out = append(out, c)
		}
	}
	return out
}

// quoteJSON renders a message the way a JSON string literal carries it, so the
// expectations above can be written as the plain sentence the server sends.
func quoteJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

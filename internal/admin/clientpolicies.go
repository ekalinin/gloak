package admin

import (
	_ "embed"
	"encoding/json"
	"io"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
)

// The four client-policy operations of the Realms Admin tag, and the two
// client-type ones beside them. See section 2 of
// docs/superpowers/specs/2026-08-29-p4-multi-realm-design.md for why they are
// P4's, and the "Client policies" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.

// globalClientProfilesJSON is Keycloak 26.7.1's ten built-in client profiles,
// recorded verbatim from
// GET /admin/realms/master/client-policies/profiles?include-global-profiles=true
// on 2026-08-29.
//
// **It is data rather than Go structs on purpose.** Every `configuration`
// inside it is a Java map whose keys are not in alphabetical order -
// `{"auto-configure":true,"allow-token-response-type":false}` is one of them -
// and marshalling it from a Go map would sort them, which is the divergence
// this project's whole comparison exists to catch. Held as recorded bytes and
// written through unchanged, the order is whatever Keycloak sent.
//
// Nothing in Gloak reads it: the profiles are served, not enforced.
//
//go:embed globalclientprofiles.json
var globalClientProfilesJSON []byte

// globalClientPoliciesJSON is the same for the policies, and 26.7.1 ships
// none: `?include-global-policies=true` was measured answering
// `"globalPolicies":[]` on master and on a created realm.
var globalClientPoliciesJSON = json.RawMessage(`[]`)

// clientProfilesResponse is GET .../client-policies/profiles.
//
// The `globalProfiles` key appears only under `include-global-profiles=true`,
// which is what omitempty on a json.RawMessage expresses: the recorded array is
// 9 KB of bytes when asked for and a nil slice when not.
type clientProfilesResponse struct {
	Profiles       []clientProfile `json:"profiles"`
	GlobalProfiles json.RawMessage `json:"globalProfiles,omitempty"`
}

type clientPoliciesResponse struct {
	Policies       []clientPolicy  `json:"policies"`
	GlobalPolicies json.RawMessage `json:"globalPolicies,omitempty"`
}

// readClientProfiles serves GET /admin/realms/{realm}/client-policies/profiles.
func (h *handler) readClientProfiles(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	rep, err := h.realmRepresentationOf(r.Context(), rc.realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := clientProfilesResponse{Profiles: rep.ClientProfiles.Profiles}
	if r.URL.Query().Get("include-global-profiles") == "true" {
		out.GlobalProfiles = globalClientProfilesJSON
	}
	writeAdminJSON(w, out)
}

// readClientPolicies serves GET /admin/realms/{realm}/client-policies/policies.
func (h *handler) readClientPolicies(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	rep, err := h.realmRepresentationOf(r.Context(), rc.realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := clientPoliciesResponse{Policies: rep.ClientPolicies.Policies}
	if r.URL.Query().Get("include-global-policies") == "true" {
		out.GlobalPolicies = globalClientPoliciesJSON
	}
	writeAdminJSON(w, out)
}

// updateClientProfiles serves PUT /admin/realms/{realm}/client-policies/profiles.
//
// It **replaces** the realm's profiles. They are the same state the realm
// representation's `clientProfiles` key carries, measured both ways: a PUT here
// changes what GET /admin/realms/{realm} answers, and a PUT there changes what
// this route answers. So there is one place they live and it is the settings
// blob.
func (h *handler) updateClientProfiles(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body clientProfiles
	if !decodeClientPolicyBody(w, r, &body, "clientProfiles") {
		return
	}
	if body.Profiles == nil {
		body.Profiles = []clientProfile{}
	}
	h.writeRealmSettings(w, r, rc, func(rep *realmRepresentation) bool {
		rep.ClientProfiles = body
		return true
	})
}

// updateClientPolicies serves PUT /admin/realms/{realm}/client-policies/policies.
//
// The one validation this cut performs is the one it can name from the realm's
// own state: a policy naming a profile the realm does not have is refused. The
// executor and condition inventories belong to engines Gloak has not built, so
// a body naming an unknown executor is accepted here and refused by Keycloak.
func (h *handler) updateClientPolicies(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body clientPolicies
	if !decodeClientPolicyBody(w, r, &body, "clientPolicies") {
		return
	}
	if body.Policies == nil {
		body.Policies = []clientPolicy{}
	}
	h.writeRealmSettings(w, r, rc, func(rep *realmRepresentation) bool {
		known := make(map[string]bool, len(rep.ClientProfiles.Profiles))
		for _, p := range rep.ClientProfiles.Profiles {
			known[p.Name] = true
		}
		for _, policy := range body.Policies {
			for _, name := range policy.Profiles {
				if !known[name] {
					httpx.WriteAdminError(w, http.StatusBadRequest,
						"Policy "+policy.Name+" contains invalid profile "+name)
					return false
				}
			}
		}
		rep.ClientPolicies = body
		return true
	})
}

// writeRealmSettings reads the realm's representation, lets apply change it,
// and stores it again. apply returns false when it has already answered.
func (h *handler) writeRealmSettings(w http.ResponseWriter, r *http.Request, rc *reqContext, apply func(*realmRepresentation) bool) {
	rep, err := h.realmRepresentationOf(r.Context(), rc.realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !apply(&rep) {
		return
	}
	rc.realm.Settings = marshalRealmSettings(&rep)
	if err := h.store.Realms().Update(r.Context(), rc.realm); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// **No Cache-Control on this 204.** PUT .../default-groups/{id} carries
	// `no-cache` and this one carries nothing at all - two PUTs in one cut,
	// opposite answers, measured on each. X-Frame-Options is present because the
	// request declares application/json, which is httpx.WriteNoContent's rule.
	httpx.WriteNoContent(w, r)
}

// decodeClientPolicyBody reads either PUT's body. Its two rejections are two
// different error families on one endpoint, and field names the one the
// empty-body message spells out.
//
// **An absent body is a 400 here where PUT /admin/realms/{realm} answers a
// 500** for the same absence, so the decoder cannot be shared with that route
// however alike the two look.
//
// A body carrying an unrecognised field is a third measured rejection - 400
// `Invalid json representation for ClientProfilesRepresentation. Unrecognized
// field "nosuchfield" at line 1 column 20.` - and it is **not** reproduced
// here, the same choice PUT /admin/realms/{realm} made for its own copy of that
// error. The column is a function of the request body, so serving it means
// reproducing Jackson's parser positions, and a wrong column is worse than an
// honest gap. The conformance case for it is Recorded, not Implemented.
func decodeClientPolicyBody(w http.ResponseWriter, r *http.Request, into any, field string) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Passing null "+field+" not allowed")
		return false
	}
	if err := json.Unmarshal(body, into); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return false
	}
	return true
}

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// updatePasswordAction is the required action a temporary password adds.
// Measured: after a reset carrying temporary true, the user representation's
// requiredActions holds exactly this.
const updatePasswordAction = "UPDATE_PASSWORD"

// passwordCredentialType is Keycloak's CredentialRepresentation.type for a
// password.
const passwordCredentialType = "password"

// credentialRepresentation is what GET .../credentials emits, in the field
// order measured 2026-08-23.
//
// **No hash leaves.** The recorded body carries id, type, an optional
// userLabel, createdDate and credentialData, and nothing else - no value, no
// salt, no secretData. credentialData describes how the secret was hashed so a
// client can tell argon2 from pbkdf2; it never describes the secret.
type credentialRepresentation struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	UserLabel      string `json:"userLabel,omitempty"`
	CreatedDate    int64  `json:"createdDate"`
	CredentialData string `json:"credentialData"`
}

// credentialData is the object Keycloak serialises **into a JSON string** and
// puts in credentialData. It is a string, not a nested object, which is why it
// is marshalled separately and the result assigned.
//
// The key order is measured: hashIterations, algorithm, additionalParameters.
type credentialData struct {
	HashIterations       int             `json:"hashIterations"`
	Algorithm            string          `json:"algorithm"`
	AdditionalParameters json.RawMessage `json:"additionalParameters"`
}

// argon2ParameterOrder is the order Keycloak serialises an argon2 credential's
// additionalParameters in: a Java map's hash order, and not alphabetical.
//
// It is written out by hand rather than marshalled from the map because the
// suite cannot sort it. Case.UnorderedKeys reaches objects in the JSON
// document, and this object is inside a *string* value - so Go's alphabetical
// map order would differ from Keycloak's on every recording with nothing able
// to normalise it away.
var argon2ParameterOrder = []string{"hashLength", "memory", "type", "version", "parallelism"}

// additionalParametersJSON writes the parameters in Keycloak's measured order.
//
// The order is only measured for argon2's five keys. A credential carrying a
// different set - pbkdf2, or an argon2 credential from some future version
// with another parameter - falls back to encoding/json's alphabetical order,
// which is a guess and is marked as one here rather than silently presented as
// contract.
func additionalParametersJSON(params map[string][]string) (json.RawMessage, error) {
	ordered := len(params) == len(argon2ParameterOrder)
	if ordered {
		for _, k := range argon2ParameterOrder {
			if _, ok := params[k]; !ok {
				ordered = false
				break
			}
		}
	}
	if !ordered {
		return json.Marshal(params)
	}

	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range argon2ParameterOrder {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(params[k])
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// passwordRepresentation is the body reset-password takes.
//
// Measured: **the type field is ignored.** A reset naming type "otp" answers
// 204 and replaces the password credential anyway - same id, refreshed
// createdDate, userLabel cleared. So this endpoint sets a password whatever it
// is told, and reproducing that means not branching on the type.
type passwordRepresentation struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

// listCredentials serves GET /admin/realms/{realm}/users/{user-id}/credentials.
//
// A user with none answers 200 and [], and view-users is enough - the body
// carries no secret, so reading it is a view operation.
func (h *handler) listCredentials(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	creds, err := h.store.Users().ListCredentials(r.Context(), user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := make([]credentialRepresentation, 0, len(creds))
	for _, c := range creds {
		rep, err := credentialRepresentationOf(c)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out = append(out, rep)
	}
	writeAdminJSON(w, out)
}

// resetPassword serves PUT /admin/realms/{realm}/users/{user-id}/reset-password.
//
// Measured: 204, no Cache-Control, and a body with no value answers 400
// {"error":"No password provided"} - the bare-prose shape, not errorMessage
// and not the OAuth one, which is a third family on the user endpoints.
//
// temporary true adds UPDATE_PASSWORD to the user's requiredActions; temporary
// false removes it, so the flag is not write-once.
func (h *handler) resetPassword(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	var rep passwordRepresentation
	if err := json.Unmarshal(raw, &rep); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return
	}
	if rep.Value == "" {
		httpx.WriteMessageError(w, http.StatusBadRequest, "No password provided")
		return
	}

	cred, err := h.newPasswordCredential(r.Context(), user, rep.Value)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.store.Users().SetCredential(r.Context(), cred); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	updated := *user
	updated.RequiredActions = withAction(user.RequiredActions, updatePasswordAction, rep.Temporary)
	if err := h.store.Users().Update(r.Context(), &updated); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// deleteCredential serves DELETE .../users/{user-id}/credentials/{credential-id}.
//
// Measured: 204 with Cache-Control: no-cache, and a second delete of the same
// id answers 404 {"error":"Credential not found"} - a fourth not-found
// spelling, after the client's, the user's and the realm's.
func (h *handler) deleteCredential(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	err := h.store.Users().DeleteCredential(r.Context(), user.ID, r.PathValue("credentialID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeCredentialNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// setCredentialLabel serves PUT .../credentials/{credential-id}/userLabel.
//
// **The body is text/plain, not JSON.** Measured: sending application/json
// answers 415 with {"error":"The content-type header value did not match the
// value in @Consumes"}, so the label is the raw body rather than a JSON
// string. That, and the fact that the 204 therefore carries no
// application/ Content-Type, is why this response omits X-Frame-Options -
// see httpx.WriteNoContent.
func (h *handler) setCredentialLabel(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	cred, ok := h.credentialFromPath(w, r, rc)
	if !ok {
		return
	}
	label, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	cred.Label = string(label)
	if err := h.store.Users().UpdateCredential(r.Context(), cred); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// moveCredentialToFirst serves POST .../credentials/{credential-id}/moveToFirst.
func (h *handler) moveCredentialToFirst(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	h.moveCredential(w, r, rc, "")
}

// moveCredentialAfter serves POST .../credentials/{credential-id}/moveAfter/{new-previous-credential-id}.
//
// Measured: a target that does not exist still answers 204. Only the
// credential being moved is checked, which is why the unknown-target case is
// not an error here.
func (h *handler) moveCredentialAfter(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	h.moveCredential(w, r, rc, r.PathValue("previousID"))
}

// moveCredential reorders one credential, either to the front or behind
// another.
//
// With one credential per type and no way to create a second, this is
// observably a no-op on every realm Gloak can currently produce - which is why
// it is written against Priority rather than against a list order that does
// not exist yet. See the migration for why the one-per-type constraint stayed.
func (h *handler) moveCredential(w http.ResponseWriter, r *http.Request, rc *reqContext, afterID string) {
	cred, ok := h.credentialFromPath(w, r, rc)
	if !ok {
		return
	}
	creds, err := h.store.Users().ListCredentials(r.Context(), cred.UserID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	ordered := make([]*model.Credential, 0, len(creds))
	for _, c := range creds {
		if c.ID != cred.ID {
			ordered = append(ordered, c)
		}
	}
	at := 0
	if afterID != "" {
		at = len(ordered)
		for i, c := range ordered {
			if c.ID == afterID {
				at = i + 1
				break
			}
		}
	}
	ordered = slices.Insert(ordered, at, cred)

	for i, c := range ordered {
		if c.Priority == i {
			continue
		}
		c.Priority = i
		if err := h.store.Users().UpdateCredential(r.Context(), c); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	httpx.WriteNoContent(w, r)
}

// disableCredentialTypes serves PUT .../users/{user-id}/disable-credential-types.
//
// Measured: 204 for any list, including ["password"], and nothing observable
// changes - the credential stays, and the user's disableableCredentialTypes
// stays []. Only credential types a provider declares disableable can be
// disabled, and on a bootstrapped master realm none is. So the endpoint is a
// 204 that does nothing, and that is the contract rather than a gap.
func (h *handler) disableCredentialTypes(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if _, ok := h.userFromPath(w, r, rc); !ok {
		return
	}
	var types []string
	if err := json.NewDecoder(r.Body).Decode(&types); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return
	}
	httpx.WriteNoContent(w, r)
}

// credentialFromPath resolves both path segments. The user is checked first:
// measured, a request naming an unknown user and a real credential answers
// "User not found" rather than "Credential not found".
func (h *handler) credentialFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.Credential, bool) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return nil, false
	}
	cred, err := h.store.Users().CredentialByID(r.Context(), user.ID, r.PathValue("credentialID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeCredentialNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return cred, true
}

func writeCredentialNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Credential not found")
}

// credentialRepresentationOf converts a stored credential for the wire.
//
// credentialData is marshalled and then assigned as a string, which is what
// makes it appear escaped in the response. Marshalling it inline as an object
// would produce valid JSON that differs from Keycloak's byte for byte.
func credentialRepresentationOf(c *model.Credential) (credentialRepresentation, error) {
	params, err := additionalParametersJSON(c.AdditionalParameters)
	if err != nil {
		return credentialRepresentation{}, err
	}
	data, err := json.Marshal(credentialData{
		HashIterations:       c.HashIterations,
		Algorithm:            c.Algorithm,
		AdditionalParameters: params,
	})
	if err != nil {
		return credentialRepresentation{}, err
	}
	return credentialRepresentation{
		ID:             c.ID,
		Type:           c.Type,
		UserLabel:      c.Label,
		CreatedDate:    c.CreatedDate,
		CredentialData: string(data),
	}, nil
}

// Argon2id parameters, measured on the credential Keycloak 26.7.1 creates for
// its own administrator. These are the *creation* parameters and belong here:
// this endpoint creates a password. internal/auth goes on reading its
// parameters from the stored credential, so a password hashed with different
// ones keeps verifying.
const (
	argonTime      = 5
	argonMemoryKiB = 7168
	argonThreads   = 1
	argonKeyLength = 32
	saltLength     = 16
)

// newPasswordCredential hashes a new password for a user, reusing the id of
// the credential it replaces.
//
// Keeping the id is measured: a reset-password leaves the credential's id
// alone while refreshing createdDate and clearing userLabel. A client that
// recorded the id before a reset still addresses the same credential after it.
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

// withAction adds or removes one required action, keeping the rest.
func withAction(actions []string, action string, want bool) []string {
	out := make([]string, 0, len(actions)+1)
	for _, a := range actions {
		if a != action {
			out = append(out, a)
		}
	}
	if want {
		out = append(out, action)
	}
	return out
}

// logoutUser serves POST /admin/realms/{realm}/users/{user-id}/logout.
//
// Measured: 204, and it is idempotent - a user who is already logged out gets
// 204 too, so "no sessions to end" is a success rather than a 404. An unknown
// user still answers "User not found".
//
// The 204 carries no Cache-Control and, when the request declares no
// Content-Type, no X-Frame-Options. That is the eighth confirmation of the
// Content-Type rule and the first on a POST: the same request with
// application/json carries the header.
func (h *handler) logoutUser(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	if err := h.store.Sessions().DeleteUserSessions(r.Context(), rc.realm.ID, user.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// Measured: the logout also stamps the user's notBefore with the moment it
	// happened, which the user representation then shows. Without this the
	// endpoint's only visible effect would be its status code.
	updated := *user
	updated.NotBefore = int(time.Now().Unix())
	if err := h.store.Users().Update(r.Context(), &updated); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The two cluster-node writes, and the third route beside them that this cut
// does not take.
//
// `GET .../test-nodes-available` is a **two-condition rule**: it answers `{}`
// unless the client has an `adminUrl` **and** at least one registered node -
// either alone gives `{}` - and with both it answers
// `{"failedRequests":["<adminUrl>"]}`, because it performs an outbound push to
// each node and reports which of them answered. Measured 2026-09-05 in all
// three states. Gloak makes no such request and signing one is `internal/token`'s
// work, so pinning the `{}` alone would be a handler that answers `{}` to every
// input it can reach - which is the shape this project has been caught by
// before.

// guardClientSubject is the third combinator in this package with the same
// three stages, and it is not either of the other two.
//
// Measured on both node writes, one role at a time:
//
//	no admin role at all, unknown client   403
//	no admin role at all, real client      403
//	view-clients,        unknown client    404 Could not find client
//	view-clients,        real client       403
//	manage-clients,      real client       204
//
// So the order is realm, caller, a **coarse** gate of clientsReadRoles, the
// client, and then the route's own roles - `guardUserSubject`'s shape with a
// client in place of the subject, and Keycloak's id-phishing branch in the
// middle.
//
// It is not `h.guard("manage-clients", …)`, which `PUT /clients/{uuid}` uses:
// that checks the role first and would answer 403 where the reference answers
// 404. It is not `guardAuthz`, which resolves a resource server as well and
// refuses without one. It is not `guardClientFeature`, which has no role list
// at all because its refusal precedes authorization. Three files, three
// combinators, one middle stage - and collapsing them means picking one of
// three different answers for the routes that do not want it.
func (h *handler) guardClientSubject(fine []string, next func(http.ResponseWriter, *http.Request, *reqContext, *model.Client)) http.HandlerFunc {
	return h.guardAnyRejecting(clientsReadRoles, writeForbidden, func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		client, ok := h.clientFromPath(w, r, rc)
		if !ok {
			return
		}
		if !rc.caller.hasAny(fine) {
			writeForbidden(w)
			return
		}
		next(w, r, rc, client)
	})
}

// registeredNodes is a client's `registeredNodes` map on the wire.
//
// **It is a Java map serialised through the *sized* HashMap constructor**, and
// that is measured rather than assumed. Three key sets, each read back off a
// live 26.7.1 on 2026-09-05:
//
//	inserted kn1, kn2                came back kn2, kn1
//	inserted kn1, kn2, zzz, aaa      came back aaa, zzz, kn2, kn1
//	inserted 127.0.0.1, ct3          came back 127.0.0.1, ct3
//
// `javamap.SizedKeyOrder` places **all three**. `javamap.KeyOrder` places the
// first two and gets the third the other way round, and that third pair does
// **not** collide - at the no-argument constructor's 16 buckets they land in 14
// and 3 - so it is a real disagreement between the two constructors rather than
// the chaining javamap says it cannot resolve. It is the same split AGENTS.md
// records between the component configs and the identity providers: one family
// each, one function apart.
//
// Neither sorting nor insertion order explains any of the three, which is what
// rules out the two cheap answers before this one is reached.
//
// The keys are handed over **sorted** rather than in insertion order, and this
// type therefore stores no insertion order. That is exact for every set with no
// bucket collision, which is all three above; a colliding set would chain in an
// order nothing observable reveals, which is javamap's documented limit and not
// something a sequence column here could fix.
type registeredNodes map[string]int64

func (n registeredNodes) MarshalJSON() ([]byte, error) {
	keys := make([]string, 0, len(n))
	for k := range n {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range javamap.SizedKeyOrder(len(keys), keys) {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.WriteString(strconv.FormatInt(n[k], 10))
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// clientNodeRequest is the body `POST .../nodes` takes. Keycloak's
// representation carries more, and this decode is **not** strict: an unknown
// field beside a good `node` answered 204, where the federated-identity write
// next door answers a 400 naming the field. Two writes in one cut, opposite
// answers to the same fault.
type clientNodeRequest struct {
	Node string `json:"node"`
}

// registerClientNode serves POST /admin/realms/{realm}/clients/{client-uuid}/nodes.
//
// 204, and **no `Cache-Control`** - where its `DELETE` sibling one path segment
// away carries `no-cache`. That is the per-endpoint pinning AGENTS.md records,
// and this pair is the cheapest counterexample yet to any rule stated over the
// verb or the status.
//
// Three failure shapes, all measured:
//
//	no body at all             500 unknown_error   (Keycloak's own defect)
//	{} or a body with no node  400 {"error":"Node not found in params"}
//	a malformed body           400 Cannot parse the JSON, invalid_request
//
// The registration is an **upsert**: the same node name posted twice answers
// 204 both times and leaves one entry carrying the second timestamp.
func (h *handler) registerClientNode(w http.ResponseWriter, r *http.Request, rc *reqContext, client *model.Client) {
	if !requireJSONBody(w, r) {
		return
	}
	if r.ContentLength == 0 {
		writeUserUnknownError(w)
		return
	}
	var req clientNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeUserCannotParse(w, "invalid_request")
		return
	}
	if req.Node == "" {
		httpx.WriteMessageError(w, http.StatusBadRequest, "Node not found in params")
		return
	}
	// Unix **seconds**. A node registered on 2026-09-05 read back as
	// 1788641822, ten digits, where every timestamp on the user representation
	// is thirteen.
	if err := h.store.Clients().RegisterNode(r.Context(), client.ID, req.Node, time.Now().Unix()); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// unregisterClientNode serves
// DELETE /admin/realms/{realm}/clients/{client-uuid}/nodes/{node}.
//
// 204 with `Cache-Control: no-cache`, and a node that is not registered is
//
//	404 {"error":"Client does not have node "}
//
// with a **trailing space and no node name**. Confirmed by hexdump on
// 2026-09-05: the body's last five bytes before the closing quote are
// `node ` - Keycloak builds the message by concatenation and hands it nothing
// to concatenate. Interpolating the name here is the tidy-up that breaks it.
func (h *handler) unregisterClientNode(w http.ResponseWriter, r *http.Request, rc *reqContext, client *model.Client) {
	err := h.store.Clients().UnregisterNode(r.Context(), client.ID, r.PathValue("node"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.WriteMessageError(w, http.StatusNotFound, "Client does not have node ")
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

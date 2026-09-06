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

// The two cluster-node writes and the read beside them.
//
// **`GET .../test-nodes-available` was written down here as a two-condition
// rule and it is one condition.** The 2026-09-05 measurement recorded "`{}`
// unless the client has an `adminUrl` **and** at least one registered node -
// either alone gives `{}`". Re-measured 2026-09-06 across all four cells, with
// the node registrations made through the sibling write above:
//
//	no adminUrl, no node        {}
//	no adminUrl, one node       {}
//	adminUrl,    no node        {"failedRequests":["http://10.255.255.1:9/adm"]}
//	adminUrl,    one node n1    {"failedRequests":["http://n1:9/adm"]}
//
// The condition is a non-empty **effective** adminUrl - `rootUrl` is resolved
// into a relative one first, and an adminUrl that is the empty string is the
// `{}` case even with a node registered. The registered nodes decide the
// *contents*: each contributes the adminUrl with its **host replaced by the
// node's name**, keeping the scheme, the port and the path, which is why
// `https://app.example.org/callback` with nodes `zzz, aaa, mmm` answers
// `https://aaa/callback`, `https://mmm/callback`, `https://zzz/callback`.
//
// That list is **sorted**, and it is not the map's order: `registeredNodes`
// serialises `{kn1, kn2}` as `kn2, kn1` and `failedRequests` answers
// `kn1, kn2` for the same client in the same response family. One map, two
// orders, and the second is not `javamap`'s.
//
// See testNodesAvailable below for why Gloak answers `{}` to every client it
// can hold, and why that is a statement about the model rather than a stub.

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

// testNodesAvailable serves
// GET /admin/realms/{realm}/clients/{client-uuid}/test-nodes-available.
//
// **`{}`, and the reason is `model.Client`'s field list rather than an unbuilt
// branch.** The endpoint's one condition is a non-empty `adminUrl`, and Gloak
// has no such field - not on `model.Client` and not on the client
// representation, which `sessions.go` already records twice for `logout-all`'s
// success list and for `push-revocation`. So the non-empty case is not a branch
// this handler declines to take, it is a state no client this server can hold
// reaches, and adding the field is the cut that has to build the outbound push
// with it: Keycloak reports a node as failed **because the push to it failed**,
// so a handler that listed the nodes without asking them would be inventing an
// answer rather than measuring one. `pushRealmRevocation` answers its own empty
// case for the same reason and with the same one line.
//
// The `{}` is `globalRequestResult{}`'s bytes, the same type the two
// push-revocation routes and `logout-all` write, because it is the same
// `GlobalRequestResult`: `failedRequests` and `successRequests` are both
// omitted when empty and Keycloak sends `{}`.
//
// **It carries `Cache-Control: no-cache` and `POST .../push-revocation` does
// not**, measured on the same container in the same sweep. Same body, same
// type, same tag, one path segment apart, and the header splits them - which
// is the per-endpoint pinning AGENTS.md records, now with a third pair inside
// this one file after the node write and the node delete.
//
// Guard: `manage-clients` alone, and `view-clients` is **403**. Measured
// 2026-09-06 over nineteen single `master-realm` roles with `GET /clients` as
// a control that differs. The resolution order is the two node writes' -
// realm, caller, the coarse `clientsReadRoles` gate, the client, then the
// route's own role - so a `view-clients` caller gets `Could not find client`
// for a UUID that resolves to nothing and 403 for one that resolves, and a
// `query-clients` caller gets exactly the same pair. `guardClientSubject`
// unchanged, which is what makes this the third route on that combinator.
//
// The wrong verbs disagree with each other: `POST`, `PUT` and `DELETE` answer
// `404 {"error":"HTTP 404 Not Found"}` and **`PATCH` answers a real 405**. That
// is the protocol mappers' shape - PATCH alone - met on a second family, and
// Gloak sends 404 to all four. See F31.
func (h *handler) testNodesAvailable(w http.ResponseWriter, r *http.Request, rc *reqContext, client *model.Client) {
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, globalRequestResult{})
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

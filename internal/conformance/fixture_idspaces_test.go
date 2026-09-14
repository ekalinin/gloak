package conformance

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// F234: the fixture id spaces, and one sweep over all of them.
//
// F230 found the shape in the identity providers and
// TestNoTwoFixturesMintOneIdentityProviderID closed it for that one family.
// F234 is the observation that nothing enumerated the others. This file is the
// enumeration and the sweep.
//
// **Every space below is global, and none of them is the same space as any
// other.** Both halves were measured against a live Keycloak 26.7.1 on
// 2026-09-13 rather than reasoned about: one id was offered to all nine
// families in one realm and all nine creates answered 201, so the per-family
// id prefixes the fixtures use are tidiness and not a requirement - and a
// client id, a client scope id and a component id are each global across
// realms, although all three objects live inside one.
//
// **What a collision answers is not shared, and assuming it was is the mistake
// this file exists to stop.** Three of the nine do not answer 409: the
// identity provider answers a **500** across realms, and the two authz stores
// that own a row answer **201 and silently rename it**.
//
// The reason a global id space is dangerous here and nowhere else is the
// recorder: `make record` drives almost every case against one shared
// container, so two fixtures that are fine apart meet. A create that loses the
// race answers a status `idempotentCreate` accepts, the fixture reports
// success having created nothing, and the case addressing the losing object
// measures a server it never reached. Nothing in the tree fails.

// idRoute is one create route that mints into an id space.
//
// A space can have several: a protocol mapper id is minted by five routes and
// they are one space, which is why the sweep pools a space's routes into one
// map instead of running per route.
type idRoute struct {
	Method string
	// Path is a regular expression matched against the request path. It is not
	// a plain suffix because two of these routes end in a path parameter -
	// `PUT .../clients/{uuid}` and `POST .../instances/{alias}/mappers` - and a
	// suffix cannot say "one more segment".
	Path string
	// Nested says where the creates are in the body:
	//
	//	""   the body is itself one create
	//	"."  the body is an **array** of creates - the batch route
	//	else the name of the body field holding an array of nested creates
	//
	// A nested create is a real create: POST /clients with a protocolMappers
	// array creates a client *and* its mappers, and they outlive the request
	// the same way. That is the pollution guard's rule arriving here.
	Nested string
	// IDKey is the key holding the id and NameKey the key holding the name, at
	// the level Nested names.
	IDKey   string
	NameKey string
	// EnclosingNameKey names the **container** of a nested create, and is empty
	// when the path already identifies it.
	//
	// It is here because "one id for one name is harmless" is only true when
	// the two mints are the same object, and two mappers called
	// `gloak-probe-mapper` under two different clients are not. The path says
	// which client for `.../models` and for the PUT; for a mapper nested inside
	// its client's own create, the body does.
	EnclosingNameKey string
}

// idSpace is one family of objects a fixture mints a **literal** id for.
//
// A create carrying no id gets a server-minted UUID, which cannot collide with
// this tree's literals, so only the literals are in scope.
type idSpace struct {
	// Object names the family, for the failure message.
	Object string
	Routes []idRoute
	// Collision is what a colliding create answers on a live 26.7.1, measured.
	// It is in the failure message because the answer differs per family and
	// reading the identity provider's into another one is exactly what F234
	// warned against.
	Collision string
	// Floor is the number of distinct literal ids the sweep must find in this
	// space.
	//
	// A sweep that matches nothing passes, and a passing sweep that matched
	// nothing is indistinguishable from a correct one. One floor over the whole
	// table would be satisfied by the eight spaces that still match while the
	// ninth went quiet, so the floor is **per space**.
	Floor int
	// RepeatIsHarmless is whether `idempotentCreate`'s name is true here: does
	// running one of this space's creates twice leave what the first one made.
	//
	// **It is false in exactly two spaces and that is F239.** Everywhere else a
	// repeat is refused and the first row survives, which is the premise the
	// whole harness rests on - the recorder shares one container, so a fixture
	// two cases name runs its creates twice. On the two authz upserts the second
	// create *wins*, so there is no refusal to swallow and no status that can
	// report it.
	//
	// This is a separate field from Collision rather than a sentence inside it
	// because Collision is prose for a failure message and nothing compares it
	// to anything. This one is read by two tests.
	RepeatIsHarmless bool
}

// fixtureIDSpaces is the enumeration F234 asked for: nine spaces over thirteen
// routes.
//
// **NameKey is what makes the sweep worth reading.** Two fixtures may share an
// id deliberately, and five pairs in this tree do - idp-minimal and idp-taken
// mint one internalId for one alias on purpose. A uniqueness check would report
// all five, and a test that reports something deliberate is a test people learn
// to ignore.
//
// The harmless case is not "one id, one name"; it is **one id, one object** -
// the same route, the same container and the same name, so that the two
// fixtures are building the same thing and the loser's refusal leaves exactly
// what the case wanted. The difference is not pedantry: one name in two
// **realms** is one name and two objects, the loser is stranded in eight of the
// nine spaces, and the fixture families that keep one realm per case are one
// copy-paste from it. See containerOf.
//
// See docs/superpowers/handover/fixture-id-spaces.md for the probes.
var fixtureIDSpaces = []idSpace{
	{
		Object: "client",
		Routes: []idRoute{{http.MethodPost, `/clients$`, "", "id", "clientId", ""}},
		// Two bodies, decided by which realm holds the winner. In the same
		// realm it is 409 `Duplicate resource error`; in another realm it is
		// 409 `Client <the new clientId> already exists` - naming the client
		// that does **not** exist, which is the identity provider's shape
		// turning up on a second family. idempotentCreate accepts both.
		Collision:        "409; in another realm the body names the client that does not exist",
		Floor:            47,
		RepeatIsHarmless: true,
	},
	{
		Object: "client scope",
		Routes: []idRoute{{http.MethodPost, `/client-scopes$`, "", "id", "name", ""}},
		// 409 `Client Scope <the new name> already exists` in the same realm
		// and in another one alike - again naming the scope that does not
		// exist. Neither loser is in either realm afterwards.
		Collision:        "409 naming the client scope that does not exist",
		Floor:            45,
		RepeatIsHarmless: true,
	},
	{
		Object: "protocol mapper",
		// **Five routes, one space.** F78 measured that a protocol mapper id is
		// unique across the server; this cut added the PUT after measuring that
		// it mints - see the note on the last route.
		Routes: []idRoute{
			{http.MethodPost, `/clients$`, "protocolMappers", "id", "name", "clientId"},
			{http.MethodPost, `/client-scopes$`, "protocolMappers", "id", "name", "name"},
			{http.MethodPost, `/protocol-mappers/models$`, "", "id", "name", ""},
			{http.MethodPost, `/protocol-mappers/add-models$`, ".", "id", "name", ""},
			// **A PUT on a client mints here, measured 2026-09-13.** Keycloak
			// matches the body's mappers to the client's by (protocol, name)
			// and keeps the id it already had - which is what
			// mapperRenamedByPutFixture measures, and it is why this looked
			// like an update rather than a mint. For a name the client does
			// **not** hold, the same PUT creates the mapper at the body's id:
			// 204, and the id is then taken server-wide. A PUT naming an id
			// another client holds is a 409.
			{http.MethodPut, `/clients/[^/]+$`, "protocolMappers", "id", "name", ""},
		},
		// F78's four cells: the single create answers the *name* conflict for
		// an id its own container holds and `Duplicate resource error` for one
		// another container holds; the batch route answers the generic body for
		// both. The enclosing create is rolled back either way, so a nested
		// collision strands the **client or client scope** as well as the
		// mapper - measured, and pinned by mapperIDRollbackFixture.
		Collision:        "409, F78's two bodies by route and holder, and the enclosing create is rolled back",
		Floor:            22,
		RepeatIsHarmless: true,
	},
	{
		Object: "component",
		Routes: []idRoute{{http.MethodPost, `/components$`, "", "id", "name", ""}},
		// 409 `Duplicate resource error`, in the same realm and in another one.
		// The **header set** of that 409 is not stable on the first occurrence -
		// see the note on the component-dup-id fixture and F147 - but the
		// status and the body are.
		Collision:        "409 Duplicate resource error, across realms too",
		Floor:            8,
		RepeatIsHarmless: true,
	},
	{
		Object: "identity provider",
		Routes: []idRoute{{http.MethodPost, `/identity-provider/instances$`, "", "internalId", "alias", ""}},
		// F230's family. The cross-realm cell is **not** a 409:
		// `ModelException: Identity Provider with internal id [...] does not
		// belong to realm [...]` comes out as a 500, which idempotentCreate
		// does not accept - so a cross-realm collision here is loud and a
		// same-realm one is silent. The four organization broker fixtures are
		// the ones that would meet it.
		Collision:        "409 naming the alias that does not exist; in another realm a 500",
		Floor:            22,
		RepeatIsHarmless: true,
	},
	{
		Object: "identity provider mapper",
		Routes: []idRoute{{http.MethodPost, `/identity-provider/instances/[^/]+/mappers$`, "", "id", "name", ""}},
		// Global across identity providers and across realms alike. A repeat
		// carrying the same **name** is a 400 `Failed to add mapper '<name>' to
		// identity provider [<providerId>].` with or without an id, which is
		// why idempotentCreate cannot cover this create.
		Collision:        "409 Duplicate resource error; a repeat of one name is a 400, not a 409",
		Floor:            7,
		RepeatIsHarmless: true,
	},
	{
		Object: "authz resource",
		Routes: []idRoute{{http.MethodPost, `/authz/resource-server/resource$`, "", "_id", "name", ""}},
		// **The worst cell measured, and it is not a refusal.** On the resource
		// server that owns the row a colliding create answers **201** and
		// silently renames it: a listing holding `res-one` holds `res-two`
		// afterwards and the first name is gone. No status can catch it,
		// because there is no error, and the winner is the **last** create
		// rather than the first. On another resource server, and in another
		// realm, it is 409 `Duplicate resource error` and the owner is intact.
		Collision: "201 on the owning resource server - a silent rename; 409 elsewhere",
		Floor:     57,
		// **The rename keeps `attributes` and nothing else**, re-measured
		// 2026-09-14 on a resource carrying a type, a displayName, two uris, a
		// scope and ownerManagedAccess: the repeat cleared all five and left the
		// attributes exactly as they were. Pinned by
		// admin/authz-resource-server/resource-create-repeat, which is the first
		// golden in this tree to record the destructive branch at all.
		RepeatIsHarmless: false,
	},
	{
		Object:    "authz scope",
		Routes:    []idRoute{{http.MethodPost, `/authz/resource-server/scope$`, "", "id", "name", ""}},
		Collision: "201 on the owning resource server - a silent rename; 409 elsewhere",
		Floor:     69,
		// The scope's rename keeps nothing: iconUri and displayName go with the
		// name. Its 201 is the request echoed rather than a read, so the damage
		// needs the read beside it - hence two goldens here where the resource
		// needs one. See admin/authz-resource-server/scope-create-repeat and
		// -repeat-read.
		RepeatIsHarmless: false,
	},
	{
		Object: "authz policy",
		Routes: []idRoute{{http.MethodPost, `/authz/resource-server/policy$`, "", "id", "name", ""}},
		// The sibling that refuses where the two above overwrite: same path
		// prefix, same verb, same question, and the first row survives. Three
		// stores under one resource server and one of them disagrees.
		Collision:        "409 Duplicate resource error everywhere, and the first row survives",
		Floor:            32,
		RepeatIsHarmless: true,
	},
}

// literalIDExemptions are the places a fixture body carries a UUID that is
// **not** a create's own id.
//
// A reference to an object that already exists cannot collide: two permissions
// naming one scope is what naming a scope means. The key is
// `<method> <path regexp> <json pointer>`, with array indices written `*`.
//
// It is a declared list rather than a rule about key names, because `id`,
// `_id` and `internalId` all mint somewhere and `id` also refers somewhere, so
// no spelling decides it.
var literalIDExemptions = map[string]string{
	`POST /authz/resource-server/resource$ /scopes/*/id`: "a resource naming a scope the fixture already created",
	`POST /authz/resource-server/policy$ /scopes/*`:      "a scope permission naming the scopes it covers",
	`POST /authz/resource-server/policy$ /resources/*`:   "a resource permission naming the resources it covers",
	`PUT /protocol-mappers/models/[^/]+$ /id`:            "an update, addressed by the same id in the path",
}

// fixtureUUID is the shape of every literal id in this tree. It is not RFC 4122
// validation; it is "this looks like an id somebody wrote down".
var fixtureUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// routeMatches reports whether a fixture step is on a declared route.
func routeMatches(method, pattern, stepMethod, path string) bool {
	if method != stepMethod {
		return false
	}
	ok, err := regexp.MatchString(pattern, path)
	return err == nil && ok
}

// expectsFailure reports whether a step declares that it means to be refused.
//
// **This is the data-side answer to "is this collision deliberate".**
// componentCollideStep and mapperIDRollbackFixture's second create both say
// `ExpectStatus: []int{http.StatusConflict}`, which is a fixture declaring that
// it means to lose - and both are real one-id-two-names collisions that a plain
// sweep would report. A comment saying the same thing would not be checkable,
// so the declaration has to be the one the fixture runner already reads.
//
// "Would not accept a 201" is the wrong predicate and was the first one tried:
// `POST .../protocol-mappers/add-models` answers **204**, so a route's success
// code is not 201 everywhere. Any 2xx is.
func expectsFailure(s Step) bool {
	if len(s.ExpectStatus) == 0 {
		// Empty means any 2xx - see acceptedStatus.
		return false
	}
	for _, c := range s.ExpectStatus {
		if c >= 200 && c < 300 {
			return false
		}
	}
	return true
}

// idMint is one literal id a fixture step puts into the store.
type idMint struct {
	fixture string
	// object identifies **which object** the mint is: the route it is on, the
	// container it is in, and its name. Two mints of one id are harmless
	// exactly when this is equal, because then they are two fixtures building
	// the same thing and the loser's refusal leaves what the case wanted.
	object string
	// describe is the same thing spelled for a human.
	describe string
}

// mintsIn pools every literal id one space's routes carry, keyed by id.
//
// It takes the fixture map rather than reading the package's own, so that
// TestTheSweepReportsACollisionItIsGiven can hand it a collision and check that
// the sweep says so. That is not a convenience: see the comment on that test
// for why nothing else in this file can check it.
func mintsIn(fixtures map[string]Fixture, sp idSpace) map[string][]idMint {
	out := map[string][]idMint{}
	for fname, f := range fixtures {
		for _, s := range f.Steps {
			// Two declarations, one skip, and they are not the same claim.
			// expectsFailure says the step means to lose and leaves the winner
			// untouched; Overwrites says it means to win and replace. Both are
			// deliberate one-id-two-object mints, so neither is a collision the
			// sweep should report - and each is illegal in the other's spaces,
			// which is what the two guards below check.
			if expectsFailure(s) || s.Overwrites {
				continue
			}
			for _, r := range sp.Routes {
				if !routeMatches(r.Method, r.Path, s.Request.Method, s.Request.Path) {
					continue
				}
				body := createsIn(s.Request.Body, r.Nested)
				where := containerOf(fname, s.Request.Path, s.Request.Body, r)
				for _, create := range body {
					id := jsonStringOf(create, r.IDKey)
					if !fixtureUUID.MatchString(id) {
						continue
					}
					name := jsonStringOf(create, r.NameKey)
					out[id] = append(out[id], idMint{
						fixture:  fname,
						object:   where + "\x00" + name,
						describe: fname + ": " + name + " in " + where,
					})
				}
			}
		}
	}
	return out
}

// containerOf spells the container a create lands in.
//
// **The request path is not enough on its own, twice over.** A path holding a
// `{{capture}}` means a different parent in every fixture - each authz fixture
// creates its own resource server and they all POST to
// `.../clients/{{client_uuid}}/authz/...` - so the fixture name is part of the
// container there. And a nested create's container is named in the **body**,
// not in the path, because the container is being created by the same request.
//
// The rule this protects is the one that is easy to get wrong: an id minted
// twice under one *name* in two different **realms** is a collision, not a
// shared object. The tree has none today; the eight spaces that answer a
// colliding create with a 409 would each strand the loser silently, and the
// fixture families that keep one realm per case are one copy-paste away from it.
func containerOf(fixture, path string, body []byte, r idRoute) string {
	where := path
	if strings.Contains(path, "{{") {
		where = fixture + " " + path
	}
	if r.EnclosingNameKey == "" {
		return where
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return where
	}
	return where + "/" + jsonStringOf(m, r.EnclosingNameKey)
}

// createsIn pulls the create objects out of one request body, per idRoute.Nested.
func createsIn(body []byte, nested string) []map[string]json.RawMessage {
	switch nested {
	case "":
		var m map[string]json.RawMessage
		if err := json.Unmarshal(body, &m); err != nil {
			return nil
		}
		return []map[string]json.RawMessage{m}
	case ".":
		var a []map[string]json.RawMessage
		if err := json.Unmarshal(body, &a); err != nil {
			return nil
		}
		return a
	default:
		var m map[string]json.RawMessage
		if err := json.Unmarshal(body, &m); err != nil {
			return nil
		}
		var a []map[string]json.RawMessage
		if err := json.Unmarshal(m[nested], &a); err != nil {
			return nil
		}
		return a
	}
}

// jsonStringOf reads one string field out of an already-decoded create.
func jsonStringOf(m map[string]json.RawMessage, field string) string {
	var s string
	if err := json.Unmarshal(m[field], &s); err != nil {
		return ""
	}
	return s
}

// sweepIDSpace is the ratchet: one id may be minted more than once only for one
// object.
//
// **The floor reports and does not stop.** It was a `t.Fatalf` first, which is
// the precedent's shape, and the mutation pass showed what that costs: giving
// one fixture another's id both removes an id from the space and creates a
// collision, so the floor fired, the subtest ended, and the collision the
// mutation existed to plant was never reported. A guard against looking at
// nothing must not hide what was looked at.
func sweepIDSpace(t *testing.T, sp idSpace) {
	t.Helper()
	minters := mintsIn(Fixtures, sp)
	if len(minters) < sp.Floor {
		t.Errorf("%s: the sweep found %d literal ids, want at least %d - it is "+
			"matching less than it did and would pass whatever the fixtures hold. "+
			"See F234.", sp.Object, len(minters), sp.Floor)
	}
	for _, c := range collisionsIn(minters) {
		t.Errorf("%s id %s is minted for %d different objects:\n\t\t%s\n"+
			"\tthe recorder shares one container, so the second create answers: %s.\n"+
			"\tThe fixture that loses reports success having created nothing, and the "+
			"case addressing the losing object measures a server it never reached. See F234.",
			sp.Object, c.id, len(c.where), strings.Join(c.where, "\n\t\t"), sp.Collision)
	}
}

// idCollision is one id minted for more than one object.
type idCollision struct {
	id string
	// where is one line per distinct object, sorted.
	where []string
}

// collisionsIn is the comparison the whole sweep exists to make, split out from
// the reporting so that a test can hand it a known collision and check that it
// comes back.
//
// **The sweep's two halves fail in different ways and only one of them had a
// guard.** idSpace.Floor covers the traversal - that mintsIn still matches
// something - and TestTheFixtureIDSpacesAreTheOnesMeasured covers the table.
// Neither covers this function, or the line in mintsIn that fills in the name
// it compares. See TestTheSweepReportsACollisionItIsGiven.
func collisionsIn(minters map[string][]idMint) []idCollision {
	var out []idCollision
	for id, mints := range minters {
		objects := map[string]bool{}
		var where []string
		for _, m := range mints {
			if objects[m.object] {
				continue
			}
			objects[m.object] = true
			where = append(where, m.describe)
		}
		if len(objects) < 2 {
			continue
		}
		sort.Strings(where)
		out = append(out, idCollision{id: id, where: where})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// TestNoTwoFixturesMintOneObjectID is F234's sweep over every id space.
//
// **It is keyed on one id for one object, not on uniqueness**, for the reason
// the comment on fixtureIDSpaces gives.
func TestNoTwoFixturesMintOneObjectID(t *testing.T) {
	for _, sp := range fixtureIDSpaces {
		t.Run(strings.ReplaceAll(sp.Object, " ", "-"), func(t *testing.T) {
			sweepIDSpace(t, sp)
		})
	}
}

// TestTheSweepReportsACollisionItIsGiven is the positive control on the sweep
// itself, one space at a time, and it closes a hole a review found.
//
// **Nothing else here checks that the sweep reads a name where it means a
// name.** Rewriting one line of mintsIn from r.NameKey to r.IDKey leaves a
// **coherent wrong sweep**: every id maps to exactly one "name" - itself - so
// every id is one object, no collision is ever reported, and the table, the
// floors and containerOf are all untouched and all still pass.
// TestTheFixtureIDSpacesAreTheOnesMeasured pins that the table **says**
// `NameKey: "clientId"`; it cannot see what the consumer does with it. That is
// the shape this project keeps meeting one level along: the claim is pinned and
// the use of the claim is not.
//
// **And the floor is not a backstop for it.** A planted collision made by
// giving one fixture another's id also removes an id from the space, so the
// floor happens to fire - which is what made the mutation look dead. A
// collision that arrives the way a real one would, two independently written
// fixtures each choosing the same literal, **adds** a mint and removes nothing.
// The count is unchanged, the floor is silent, and with that one line rewritten
// the whole suite is green. The `two independent fixtures` case below is
// exactly that shape, which is why it is the one this test is built on.
//
// Both directions are asserted per space, because a sweep that reported
// everything would satisfy the first half alone.
func TestTheSweepReportsACollisionItIsGiven(t *testing.T) {
	const id = "0c0111de-0000-4000-8000-000000000001"
	for _, sp := range fixtureIDSpaces {
		t.Run(strings.ReplaceAll(sp.Object, " ", "-"), func(t *testing.T) {
			for _, r := range sp.Routes {
				// Two independently written fixtures choosing one literal id
				// for two different objects, in one container. Nothing is taken
				// away, so the space's id count is unchanged and the floor
				// cannot fire: the **name** is the only thing that separates
				// them, which is exactly the line a review found unpinned.
				collide := map[string]Fixture{
					"probe-a": syntheticMint(t, r, id, "probe-object-a", "gloak-probe-one"),
					"probe-b": syntheticMint(t, r, id, "probe-object-b", "gloak-probe-one"),
				}
				got := collisionsIn(mintsIn(collide, sp))
				if len(got) != 1 || got[0].id != id {
					t.Errorf("%s %s %s: a planted collision on %s was reported as %v, "+
						"want exactly one. The sweep is not comparing what it claims to "+
						"compare, and neither the floor nor the pinned table can see it. "+
						"See F234.", sp.Object, r.Method, r.Path, id, got)
				}
				// The same id and the same name in two different containers,
				// which is the cross-realm trap containerOf exists for.
				elsewhere := map[string]Fixture{
					"probe-a": syntheticMint(t, r, id, "probe-object", "gloak-probe-one"),
					"probe-b": syntheticMint(t, r, id, "probe-object", "gloak-probe-two"),
				}
				if got := collisionsIn(mintsIn(elsewhere, sp)); len(got) != 1 {
					t.Errorf("%s %s %s: one id and one name in two containers was reported "+
						"as %v, want exactly one collision - one name in two realms is two "+
						"objects. See F234.", sp.Object, r.Method, r.Path, got)
				}
				// The same id for the same object, which is the deliberate
				// case five pairs in this tree rely on.
				share := map[string]Fixture{
					"probe-a": syntheticMint(t, r, id, "probe-object", "gloak-probe-one"),
					"probe-b": syntheticMint(t, r, id, "probe-object", "gloak-probe-one"),
				}
				if got := collisionsIn(mintsIn(share, sp)); len(got) != 0 {
					t.Errorf("%s %s %s: two fixtures building one object were reported as "+
						"%v, want none - a test that reports deliberate sharing is a test "+
						"people learn to ignore. See F234.", sp.Object, r.Method, r.Path, got)
				}
			}
		})
	}
}

// syntheticMint is one fixture whose single step mints `id` under `name` in
// `container`, shaped for the route it is on.
//
// Where the container comes from the path - which is every route except the two
// nested-in-a-create ones - `container` is the **realm**, because that is both
// the way containerOf tells two paths apart and the shape a real cross-realm
// collision would have.
//
// It checks the path it builds against the route's own pattern rather than
// trusting the substitution: a sample path that quietly stopped matching would
// leave TestTheSweepReportsACollisionItIsGiven comparing an empty map against
// an empty map, which is the vacuity this whole file is about.
func syntheticMint(t *testing.T, r idRoute, id, name, container string) Fixture {
	t.Helper()
	create := `{"` + r.IDKey + `":"` + id + `","` + r.NameKey + `":"` + name + `"}`
	var body string
	switch r.Nested {
	case "":
		body = create
	case ".":
		body = `[` + create + `]`
	default:
		body = `{"` + r.EnclosingNameKey + `":"` + container + `","` + r.Nested + `":[` + create + `]}`
	}
	// Where the container is named in the body the path is shared; where it is
	// not, the path is the only thing that can carry it. **Nesting does not
	// decide this and the first version of this helper assumed it did**: the
	// PUT route is nested and its container is the client in its path, so
	// sharing the path made two clients look like one and the control reported
	// its own scaffolding.
	realm := "gloak-probe-realm"
	if r.EnclosingNameKey == "" {
		realm = container
	}
	tail := strings.ReplaceAll(strings.TrimSuffix(r.Path, "$"), `[^/]+`, "gloak-probe-parent")
	path := "/admin/realms/" + realm + tail
	if !routeMatches(r.Method, r.Path, r.Method, path) {
		t.Fatalf("the sample path %q does not match the route %q, so this test "+
			"would compare nothing", path, r.Path)
	}
	return Fixture{State: "bootstrap", Steps: []Step{{
		Request: Request{Method: r.Method, Path: path, Body: []byte(body)},
	}}}
}

// TestContainerOfSeparatesWhatACollisionWouldSeparate pins containerOf
// directly, and it exists because the tree cannot pin it.
//
// containerOf is what turns "one id, one name" into "one id, one object". Every
// distinction it draws is about a collision the tree **does not currently
// have**: no id is minted in two realms, under two resource servers or in two
// containers today, so neutering the whole function to a constant leaves
// TestNoTwoFixturesMintOneObjectID green. That is the inert-guard shape this
// project keeps meeting - a mechanism with no positive control is a mechanism
// nobody will notice losing - so the claims are asserted here against what was
// measured rather than against what the fixtures happen to hold.
func TestContainerOfSeparatesWhatACollisionWouldSeparate(t *testing.T) {
	plain := idRoute{http.MethodPost, `/components$`, "", "id", "name", ""}
	nested := idRoute{http.MethodPost, `/clients$`, "protocolMappers", "id", "name", "clientId"}
	captured := idRoute{http.MethodPost, `/authz/resource-server/scope$`, "", "id", "name", ""}
	for _, tc := range []struct {
		what       string
		aF, aP, aB string
		bF, bP, bB string
		route      idRoute
		same       bool
		because    string
	}{
		{
			what: "two realms",
			aF:   "one", aP: "/admin/realms/ra/components", aB: `{"id":"x","name":"n"}`,
			bF: "two", bP: "/admin/realms/rb/components", bB: `{"id":"x","name":"n"}`,
			route: plain, same: false,
			because: "a component id is global across realms, so the second create is a 409 and the loser is stranded",
		},
		{
			what: "one realm, one route",
			aF:   "one", aP: "/admin/realms/ra/components", aB: `{"id":"x","name":"n"}`,
			bF: "two", bP: "/admin/realms/ra/components", bB: `{"id":"x","name":"n"}`,
			route: plain, same: true,
			because: "two fixtures building the same component is the deliberate case five pairs in this tree rely on",
		},
		{
			what: "two clients, one nested mapper name",
			aF:   "one", aP: "/admin/realms/ra/clients", aB: `{"clientId":"ca","protocolMappers":[{"id":"x","name":"n"}]}`,
			bF: "one", bP: "/admin/realms/ra/clients", bB: `{"clientId":"cb","protocolMappers":[{"id":"x","name":"n"}]}`,
			route: nested, same: false,
			because: "the path is the same for both creates and the container is named in the body",
		},
		{
			what: "two fixtures, one captured parent",
			aF:   "one", aP: "/admin/realms/ra/clients/{{client_uuid}}/authz/resource-server/scope", aB: `{"id":"x","name":"n"}`,
			bF: "two", bP: "/admin/realms/ra/clients/{{client_uuid}}/authz/resource-server/scope", bB: `{"id":"x","name":"n"}`,
			route: captured, same: false,
			because: "every authz fixture creates its own resource server, so one path string is two parents",
		},
	} {
		a := containerOf(tc.aF, tc.aP, []byte(tc.aB), tc.route)
		b := containerOf(tc.bF, tc.bP, []byte(tc.bB), tc.route)
		if (a == b) != tc.same {
			verb := "must differ"
			if tc.same {
				verb = "must agree"
			}
			t.Errorf("%s: containerOf %s - %s\n\tgot %q and %q",
				tc.what, verb, tc.because, a, b)
		}
	}
}

// TestTheFixtureIDSpacesAreTheOnesMeasured pins the table whole, in the shape
// TestTheProviderThatFetchesOnConstructionIsTheOneMeasured uses: compare the
// **list**, not the membership of one row, so that an entry arriving and an
// entry leaving each fail on their own.
//
// The lesson this cut inherited is that a guard counting what a sweep *visited*
// is not a guard on what it *compared*. The sweep reads NameKey, and a NameKey
// changed to the IDKey maps every id to exactly one "name", silences that space
// for ever, and leaves every floor satisfied - a coherent wrong table rather
// than a broken one. That mutation dies here and nowhere else.
func TestTheFixtureIDSpacesAreTheOnesMeasured(t *testing.T) {
	want := []struct {
		object string
		routes []idRoute
	}{
		{"client", []idRoute{{"POST", `/clients$`, "", "id", "clientId", ""}}},
		{"client scope", []idRoute{{"POST", `/client-scopes$`, "", "id", "name", ""}}},
		{"protocol mapper", []idRoute{
			{"POST", `/clients$`, "protocolMappers", "id", "name", "clientId"},
			{"POST", `/client-scopes$`, "protocolMappers", "id", "name", "name"},
			{"POST", `/protocol-mappers/models$`, "", "id", "name", ""},
			{"POST", `/protocol-mappers/add-models$`, ".", "id", "name", ""},
			{"PUT", `/clients/[^/]+$`, "protocolMappers", "id", "name", ""},
		}},
		{"component", []idRoute{{"POST", `/components$`, "", "id", "name", ""}}},
		{"identity provider", []idRoute{
			{"POST", `/identity-provider/instances$`, "", "internalId", "alias", ""}}},
		{"identity provider mapper", []idRoute{
			{"POST", `/identity-provider/instances/[^/]+/mappers$`, "", "id", "name", ""}}},
		{"authz resource", []idRoute{
			{"POST", `/authz/resource-server/resource$`, "", "_id", "name", ""}}},
		{"authz scope", []idRoute{
			{"POST", `/authz/resource-server/scope$`, "", "id", "name", ""}}},
		{"authz policy", []idRoute{
			{"POST", `/authz/resource-server/policy$`, "", "id", "name", ""}}},
	}
	if len(fixtureIDSpaces) != len(want) {
		t.Fatalf("the table holds %d id spaces, want %d: adding or removing one "+
			"silences or invents a whole family's sweep, so the list is asserted "+
			"here rather than only counted. See F234.", len(fixtureIDSpaces), len(want))
	}
	for i, w := range want {
		got := fixtureIDSpaces[i]
		if got.Object != w.object {
			t.Errorf("id space %d is %q, want %q", i, got.Object, w.object)
			continue
		}
		if len(got.Routes) != len(w.routes) {
			t.Errorf("%s has %d routes, want %d: a protocol mapper id is one space "+
				"over five routes, and dropping one leaves the ids it mints unswept",
				w.object, len(got.Routes), len(w.routes))
			continue
		}
		for j, wr := range w.routes {
			if got.Routes[j] != wr {
				t.Errorf("%s route %d is %+v, want %+v", w.object, j, got.Routes[j], wr)
			}
		}
		if got.Collision == "" {
			t.Errorf("%s records no collision answer: the whole point of the table "+
				"is that the answer differs per family", w.object)
		}
		if got.Floor < 1 {
			t.Errorf("%s has floor %d: a space with no floor passes when it matches "+
				"nothing", w.object, got.Floor)
		}
	}
}

// TestIdempotentCreateNamesTheSpacesItLiesAbout is F239 turned into something a
// run reads.
//
// `idempotentCreate` is one constant over nine different refusals, and its name
// claims a repeat is harmless. In two spaces that is false: the repeat is a 201
// that overwrites, the constant accepts 201, and the step reports success for a
// request that lost information. F239's instruction was to record where the
// claim is false **without widening the constant**, because widening it is how
// a fixture that creates nothing starts passing.
//
// So the record is the RepeatIsHarmless column and this is what stops it
// rotting. A column nothing compares is a comment with a colon in it - which is
// the defect this file already met once, in the Collision field it sits beside.
// The two names are spelled out rather than counted because a count passes when
// one space flips to false and another flips to true.
func TestIdempotentCreateNamesTheSpacesItLiesAbout(t *testing.T) {
	// idempotentCreate accepting a 2xx is the whole mechanism: if it ever stops,
	// a destructive repeat becomes loud and this test is measuring nothing.
	accepts201 := false
	for _, c := range idempotentCreate {
		if c == http.StatusCreated {
			accepts201 = true
		}
	}
	if !accepts201 {
		t.Fatalf("idempotentCreate is %v and does not accept 201: the reason a "+
			"destructive repeat is silent is that this constant waves the 201 "+
			"through, so this test asserts nothing while that is false", idempotentCreate)
	}

	want := map[string]bool{"authz resource": true, "authz scope": true}
	got := map[string]bool{}
	for _, sp := range fixtureIDSpaces {
		if !sp.RepeatIsHarmless {
			got[sp.Object] = true
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d spaces declare a repeat is not harmless, want %d: %v",
			len(got), len(want), got)
	}
	for object := range want {
		if !got[object] {
			t.Errorf("%q declares its repeat harmless, and it is not: a repeat "+
				"there answers 201 and overwrites the row. See F237 and F239.", object)
		}
	}
	for object := range got {
		if !want[object] {
			t.Errorf("%q declares its repeat is not harmless and is not one of the "+
				"two measured spaces. If a third route has been measured "+
				"overwriting, add it here with the measurement; if this is a "+
				"guess, take it out - `idempotentCreate` is silent in exactly the "+
				"spaces this list names.", object)
		}
	}
}

// TestNoStepDeclaresALossWhereARepeatWins is the half of F239 that protects the
// fixtures rather than describing them.
//
// `ExpectStatus` excluding every 2xx is how a fixture declares that it *means*
// to lose a collision - componentCollideStep and mapperIDRollbackFixture both do
// it, and mintsIn skips such a step for exactly that reason. In the two spaces
// where a repeat wins, that declaration is incoherent twice over: the refusal it
// waits for never comes, so the step fails on its own status; and if the
// declaration were ever relaxed, mintsIn would still be skipping the step, so
// the mint it makes would be invisible to the collision sweep.
//
// There is no such step today and this is a ratchet, not a bug report. The
// reason it is worth a test is that it is one copy-paste away: the two declared
// losses in this tree are both creates, both look exactly like an authz create,
// and nothing else in the file would notice the difference.
func TestNoStepDeclaresALossWhereARepeatWins(t *testing.T) {
	checked := 0
	for _, sp := range fixtureIDSpaces {
		if sp.RepeatIsHarmless {
			continue
		}
		checked++
		for name, f := range Fixtures {
			for _, s := range f.Steps {
				if !expectsFailure(s) {
					continue
				}
				for _, r := range sp.Routes {
					if !routeMatches(r.Method, r.Path, s.Request.Method, s.Request.Path) {
						continue
					}
					t.Errorf("fixture %q declares a deliberate loss on %s %s, and a "+
						"repeat in the %q space does not lose - it answers 201 and "+
						"overwrites the row. The step will fail on its own status, "+
						"and while it carries this declaration the id it mints is "+
						"invisible to the collision sweep, which skips any step that "+
						"expectsFailure. See F239.",
						name, s.Request.Method, s.Request.Path, sp.Object)
				}
			}
		}
	}
	// The vacuity guard covers the outer loop rather than the comparison: with
	// no space declaring RepeatIsHarmless false this walks nothing and passes.
	// The comparison itself is covered by the test above, which pins which two
	// spaces those are.
	if checked != 2 {
		t.Fatalf("walked %d spaces whose repeat overwrites, want 2: with none "+
			"this test passes having compared nothing", checked)
	}
}

// TestNoAuthzIDReachesTwoResourceServers is F238's half, and it is the reason
// that entry can be closed without reproducing anything.
//
// A colliding authz create does not only lose. On 26.7.1 it **damages the
// resource server that holds the winner**: measured 2026-09-14, the near
// server's scope listing answers `400 Cannot parse the JSON` and its settings a
// 500, while the resource side goes quieter still - the row vanishes from the
// listing and from its own id read while `/resource/search` still returns it.
// The row is never lost; a container restart clears all of it, so it is an
// in-process cache and not storage.
//
// Reaching it needs one id minted on **two different resource servers**, and
// that is what this forbids. It is deliberately not the same check as
// TestNoTwoFixturesMintOneObjectID: that one keys on the object and skips any
// step declaring ExpectStatus or Overwrites, and both exemptions are correct
// there because a declared loss and a declared overwrite are each harmless *on
// one server*. Neither is harmless across two, and the damage lands on the
// server that did nothing wrong - so this walks every step including the
// exempted ones and keys on the fixture alone.
//
// Every authz create path carries `{{client_uuid}}`, and every authz fixture
// builds exactly one client, so "two fixtures" and "two resource servers" are
// the same statement here. That is what makes the check cheap and what makes it
// worth writing down: the day a fixture builds two resource servers, this is the
// test that has to be reconsidered rather than silently satisfied.
func TestNoAuthzIDReachesTwoResourceServers(t *testing.T) {
	checked := 0
	for _, sp := range fixtureIDSpaces {
		if sp.RepeatIsHarmless {
			continue
		}
		owners := map[string]map[string]bool{}
		for name, f := range Fixtures {
			for _, s := range f.Steps {
				for _, r := range sp.Routes {
					if !routeMatches(r.Method, r.Path, s.Request.Method, s.Request.Path) {
						continue
					}
					for _, create := range createsIn(s.Request.Body, r.Nested) {
						id := jsonStringOf(create, r.IDKey)
						if !fixtureUUID.MatchString(id) {
							continue
						}
						checked++
						if owners[id] == nil {
							owners[id] = map[string]bool{}
						}
						owners[id][name] = true
					}
				}
			}
		}
		for id, fixtures := range owners {
			if len(fixtures) < 2 {
				continue
			}
			names := make([]string, 0, len(fixtures))
			for n := range fixtures {
				names = append(names, n)
			}
			sort.Strings(names)
			t.Errorf("%s id %s is minted by %d fixtures (%s), and each builds its "+
				"own resource server. A colliding create across two resource "+
				"servers is refused **and** poisons the one holding the winner: "+
				"its listing and settings stop answering until the container "+
				"restarts. The case that breaks is the one reading the server that "+
				"did nothing. See F238.",
				sp.Object, id, len(fixtures), strings.Join(names, ", "))
		}
	}
	// A floor over the two spaces together, because the per-space floors on the
	// table already guard the sweep that skips exempted steps and this one does
	// not skip them - so the number it sees is the table's floors plus those.
	if checked < 131 {
		t.Fatalf("walked %d authz ids across the overwriting spaces, want at least "+
			"131: this matched almost nothing and would pass whatever the fixtures "+
			"hold", checked)
	}
}

// TestOverwritesIsOnlyDeclaredWhereARepeatWins is the mirror of the test above,
// and the pair is the point.
//
// `Step.Overwrites` exempts a step from the collision sweep, so a stray one is a
// hole rather than a mistake: the id it mints stops being compared and the next
// real collision on that route goes unreported. It is only a truthful
// declaration on the two routes where a repeat answers 201 and replaces the row;
// anywhere else the repeat is refused, the step is an ordinary deliberate loss,
// and `ExpectStatus` is the field that says so.
//
// The floor is what stops this going quiet. With `Overwrites` set nowhere the
// loop compares nothing and passes, which is the shape that shipped a silent
// sweep once already - see F234 and the survivor in fixture-id-spaces.md.
func TestOverwritesIsOnlyDeclaredWhereARepeatWins(t *testing.T) {
	declared := 0
	for name, f := range Fixtures {
		for _, s := range f.Steps {
			if !s.Overwrites {
				continue
			}
			declared++
			if !onAnOverwritingRoute(fixtureIDSpaces, s.Request.Method, s.Request.Path) {
				t.Errorf("fixture %q declares Overwrites on %s %s, which is not one "+
					"of the routes where a repeat wins. That flag takes the step out "+
					"of the collision sweep, so on any other route it hides a real "+
					"collision rather than declaring a deliberate one. A step that "+
					"means to lose says so with ExpectStatus. See F239.",
					name, s.Request.Method, s.Request.Path)
			}
			if expectsFailure(s) {
				t.Errorf("fixture %q declares both Overwrites and a losing "+
					"ExpectStatus on %s %s: the two say opposite things about the "+
					"same request, and exactly one of them can be true.",
					name, s.Request.Method, s.Request.Path)
			}
		}
	}
	if declared < 1 {
		t.Fatalf("no step declares Overwrites: this test walked nothing and would " +
			"pass whatever the fixtures hold. The destructive repeat is measured by " +
			"admin/authz-resource-server/scope-create-repeat-read, whose fixture " +
			"needs the flag; if that case is gone, this guard should go with it.")
	}
}

// onAnOverwritingRoute reports whether a request is on one of the routes where
// a repeat wins, and so whether Step.Overwrites is a truthful declaration on it.
//
// It is a function rather than four lines inside the test because the test's
// floor cannot cover it. **A vacuity guard covers the traversal; the comparison
// needs its own** - the lesson F234 paid for twice - and a floor counting the
// steps that declare Overwrites is satisfied by a predicate that returns true
// for everything. TestOnAnOverwritingRouteSeparatesWhatItMustSeparate is the
// positive control, and it is the only thing in this file that can kill a
// predicate rewritten to be permissive.
func onAnOverwritingRoute(spaces []idSpace, method, path string) bool {
	for _, sp := range spaces {
		if sp.RepeatIsHarmless {
			continue
		}
		for _, r := range sp.Routes {
			if routeMatches(r.Method, r.Path, method, path) {
				return true
			}
		}
	}
	return false
}

// TestOnAnOverwritingRouteSeparatesWhatItMustSeparate hands the predicate the
// three answers it has to get right, with the table it really runs on.
//
// The first is the case that exists; the second and third are the two ways a
// permissive predicate goes wrong - a sibling route one path segment away that
// refuses its repeat, and a create in another family entirely. Both would be
// exempted from the collision sweep by a predicate that said yes to everything,
// and nothing else in this file would notice.
func TestOnAnOverwritingRouteSeparatesWhatItMustSeparate(t *testing.T) {
	const authz = "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server"
	for _, tc := range []struct {
		what   string
		method string
		path   string
		want   bool
	}{
		{"the scope create, where a repeat wins", http.MethodPost, authz + "/scope", true},
		{"the resource create, where a repeat wins", http.MethodPost, authz + "/resource", true},
		{"the policy create, one segment away, which refuses", http.MethodPost, authz + "/policy", false},
		{"the permission create, same store as the policy", http.MethodPost, authz + "/permission", false},
		{"the scope PUT, which is a replace and not a repeat", http.MethodPut, authz + "/scope/x", false},
		{"a client create, another family", http.MethodPost, "/admin/realms/master/clients", false},
		{"a component create, another family", http.MethodPost, "/admin/realms/master/components", false},
	} {
		if got := onAnOverwritingRoute(fixtureIDSpaces, tc.method, tc.path); got != tc.want {
			t.Errorf("onAnOverwritingRoute(%s %s) = %v, want %v - %s",
				tc.method, tc.path, got, tc.want, tc.what)
		}
	}
}

// TestEveryLiteralIDInAFixtureBodyIsInADeclaredSpace is the half of F234 that
// is about the **next** family rather than about the nine here.
//
// F234's complaint was not that a collision existed; it was that nothing
// enumerated the spaces, so the sweep that found one had to be done by hand. A
// table alone does not fix that: a tenth family arriving with a literal id and
// no row would be exactly as invisible as the nine were. This walks the other
// way - every UUID-shaped literal in a fixture's request body has to be a
// declared space's id or a declared exemption - so the table cannot fall behind
// the fixtures.
//
// It reads **every** method rather than POST alone, and that is not caution:
// sweeping the PUTs is what found that `PUT /clients/{uuid}` mints into the
// protocol mapper space, which the first version of this file had written off
// as an update on the strength of mapperRenamedByPutFixture's comment.
func TestEveryLiteralIDInAFixtureBodyIsInADeclaredSpace(t *testing.T) {
	declared := map[string]bool{}
	for _, sp := range fixtureIDSpaces {
		for _, r := range sp.Routes {
			declared[r.Method+" "+r.Path+" "+pointerOf(r)] = true
		}
	}
	seenExemption := map[string]bool{}
	checked := 0
	for name, f := range Fixtures {
		for _, s := range f.Steps {
			var body any
			if err := json.Unmarshal(s.Request.Body, &body); err != nil {
				continue
			}
			for _, found := range uuidPointers(body, "") {
				checked++
				if claimedBy(declared, s.Request.Method, s.Request.Path, found.pointer) {
					continue
				}
				if key, ok := exemptionFor(s.Request.Method, s.Request.Path, found.pointer); ok {
					seenExemption[key] = true
					continue
				}
				t.Errorf("fixture %q: %s %s carries the literal id %s at %s, and no "+
					"idSpace and no exemption claims it - so nothing sweeps it for "+
					"collisions. Either add a route to fixtureIDSpaces, with what a "+
					"colliding create there answers **measured**, or exempt it with "+
					"the reason it cannot collide. See F234.",
					name, s.Request.Method, s.Request.Path, found.value, found.pointer)
			}
		}
	}
	// Two vacuity guards, because there are two ways for this to go quiet. The
	// first is the sweep finding no literals at all. The second is an exemption
	// ceasing to match, which leaves a claim about a tree that no longer holds
	// it - and, worse, would let the same pointer come back as a real mint
	// unnoticed.
	if checked < 345 {
		t.Fatalf("the sweep found %d literal ids in fixture bodies, want at least "+"345: it is matching nothing and would pass whatever the fixtures hold",
			checked)
	}
	for key, why := range literalIDExemptions {
		if !seenExemption[key] {
			t.Errorf("the exemption %q (%s) matches nothing in the tree: an exemption "+
				"nothing exercises is a claim nobody checks. Remove it or fix it.", key, why)
		}
	}
}

// pointerOf spells the JSON pointer an idRoute's id sits at, in the notation
// uuidPointers produces.
func pointerOf(r idRoute) string {
	switch r.Nested {
	case "":
		return "/" + r.IDKey
	case ".":
		return "/*/" + r.IDKey
	default:
		return "/" + r.Nested + "/*/" + r.IDKey
	}
}

func claimedBy(declared map[string]bool, method, path, pointer string) bool {
	for key := range declared {
		parts := strings.SplitN(key, " ", 3)
		if len(parts) != 3 || parts[2] != pointer {
			continue
		}
		if routeMatches(parts[0], parts[1], method, path) {
			return true
		}
	}
	return false
}

func exemptionFor(method, path, pointer string) (string, bool) {
	for key := range literalIDExemptions {
		parts := strings.SplitN(key, " ", 3)
		if len(parts) != 3 || parts[2] != pointer {
			continue
		}
		if routeMatches(parts[0], parts[1], method, path) {
			return key, true
		}
	}
	return "", false
}

// uuidFound is one UUID-shaped literal and the JSON pointer it sits at, with
// array indices written `*` so two elements of one array are one place.
type uuidFound struct {
	pointer string
	value   string
}

func uuidPointers(v any, at string) []uuidFound {
	var out []uuidFound
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, uuidPointers(t[k], at+"/"+k)...)
		}
	case []any:
		for _, e := range t {
			out = append(out, uuidPointers(e, at+"/*")...)
		}
	case string:
		if fixtureUUID.MatchString(t) {
			out = append(out, uuidFound{pointer: at, value: t})
		}
	}
	return out
}

package token

// The admin console's scope evaluator previews what a client's tokens would
// look like for a given user, and Keycloak serves that preview as an ordinary
// JSON body:
//
//	GET .../clients/{uuid}/evaluate-scopes/generate-example-access-token
//	GET .../clients/{uuid}/evaluate-scopes/generate-example-id-token
//
// The two functions below render those bodies. They live here for the reason
// Introspection does - "the same claim set, one key order, changed in one
// place" - and the alternative was measured to be worse rather than merely
// untidy: a claim set built in internal/admin is a second answer to what a
// token looks like, and the first place two answers diverge is the key order
// nobody reads. That is the boundary question follow-up F148 defers for the
// two authorization `evaluate` operations, and it is answered the same way
// there: an RPT is an access token's claim set, so internal/token builds it and
// the caller supplies the inputs.
//
// **The preview's fidelity is deliberately the issuance path's, no more.** Both
// functions build the same structs Issue builds, so a claim Gloak does not put
// in a token does not appear in the preview of one either. A preview that
// disagreed with the tokens the server actually issues would be worse than one
// that agrees, and where Keycloak's set is richer - the profile and email
// mappers, measured on a user carrying a firstName - the gap is the P5 one this
// package's own doc comment declares rather than a new one.
//
// What the caller resolves, exactly as Request already requires for issuance:
// the roles, filtered by the client's evaluated scope rather than by the
// client's own scope mappings alone; the scope string; and a session. The
// session is a throwaway - Keycloak mints a fresh sid per request for a session
// that does not exist, measured across repeated identical requests - so the
// caller passes one it never stores.

// ExampleAccessClaims is the body of generate-example-access-token: the access
// token's claim set, unsigned.
//
// It returns any because accessClaims and lightweightClaims are two shapes and
// the client's attribute picks between them, which is the same choice
// (*Issuer).accessClaims already makes for a real issuance. Callers marshal it;
// nothing here writes a response.
func (i *Issuer) ExampleAccessClaims(r Request) any {
	now := i.now().UTC()
	return i.accessClaims(r, now.Unix(), now.Add(r.AccessLife).Unix())
}

// ExampleIDClaims is the body of generate-example-id-token.
//
// The access token is passed as an empty string on purpose: there is no access
// token in this exchange, so there is no at_hash to compute. Measured - the
// example ID token carries no at_hash key at all, where every issued one does -
// which is why idClaims.AtHash carries omitempty. The tag is right on both
// bodies and neither of them is a special case of the other.
func (i *Issuer) ExampleIDClaims(r Request) any {
	now := i.now().UTC()
	return i.idClaims(r, "", now.Unix(), now.Add(r.AccessLife).Unix())
}

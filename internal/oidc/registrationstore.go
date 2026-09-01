package oidc

import "sync"

// registrationStore remembers which registration access token is current for a
// client.
//
// **This is not the device store's situation and the precedent does not
// carry.** A device code is short-lived by design and Keycloak keeps it in
// Infinispan; a registered client is an ordinary client that outlives every
// process, and this cut persists it through store.ClientRepo like any other.
// What lives here is only the *jti* of the token a caller must present to read,
// update or delete it, because:
//
//   - the token is otherwise stateless - no subject, no client, no expiry, so
//     nothing in it says which client it belongs to or whether it is still the
//     current one; and
//   - a PUT rotates it and the old one is refused immediately afterwards,
//     measured, so recognising the current jti is the whole mechanism.
//
// The honest place for it is a column on the client, which is what Keycloak
// has. `model.Client` has no field for it and `internal/model` and
// `internal/store` are owned elsewhere this session. Putting it in
// `Attributes` was rejected rather than overlooked: that map is serialised
// whole into the Admin API's client representation, and a registered client's
// attributes were measured to be exactly five keys, none of them a token.
//
// **The cost is stated rather than hidden: a restart makes every outstanding
// registration access token stop working**, where Keycloak's survives. The
// client itself survives, which is the half that matters and the half the
// device store cannot claim. Filed.
type registrationStore struct {
	mu sync.Mutex
	// current maps "<realm id>\x00<client uuid>" to the jti of the token that
	// may act on it. A client with no entry has no live registration token,
	// which is every client this server did not register.
	current map[string]string
}

func newRegistrationStore() *registrationStore {
	return &registrationStore{current: map[string]string{}}
}

func registrationKey(realmID, clientUUID string) string {
	return realmID + "\x00" + clientUUID
}

// issue records jti as the current token for a client, replacing whatever was
// there. It is the rotation: the value it overwrites stops being accepted.
func (s *registrationStore) issue(realmID, clientUUID, jti string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current[registrationKey(realmID, clientUUID)] = jti
}

// holds reports whether jti is the current token for this client.
//
// An empty jti is refused outright rather than matched against a missing entry,
// which would make every client without one readable by a token carrying no
// jti at all.
func (s *registrationStore) holds(realmID, clientUUID, jti string) bool {
	if jti == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current[registrationKey(realmID, clientUUID)] == jti
}

// forget drops a client's token, which the delete does.
func (s *registrationStore) forget(realmID, clientUUID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.current, registrationKey(realmID, clientUUID))
}

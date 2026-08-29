package keys_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"path/filepath"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

// newStore opens a file-backed store with one realm in it. File-backed rather
// than in-memory: tests on in-memory SQLite have passed in this project while
// the file-backed path was broken.
func newStore(t *testing.T) (store.Store, *model.Realm) {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "gloak.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	r := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
	if err := s.Realms().Create(ctx, r); err != nil {
		t.Fatalf("Realms().Create: %v", err)
	}
	return s, r
}

func publicKey(t *testing.T, jwk jose.JSONWebKey) *rsa.PublicKey {
	t.Helper()
	pub, ok := jwk.Key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("want an RSA public key, got %T", jwk.Key)
	}
	return pub
}

func TestManagerKeepsKidAcrossRestarts(t *testing.T) {
	// F5: the kid used to change on every process start, invalidating every
	// cached JWKS a client held and making two replicas disagree.
	s, realm := newStore(t)
	ctx := context.Background()

	first, err := keys.NewManager(s).ForRealm(ctx, realm)
	if err != nil {
		t.Fatalf("first ForRealm: %v", err)
	}
	// A second Manager stands in for a second process: same store, no shared
	// cache.
	second, err := keys.NewManager(s).ForRealm(ctx, realm)
	if err != nil {
		t.Fatalf("second ForRealm: %v", err)
	}

	if first.RSAKeyID != second.RSAKeyID {
		t.Errorf("RSA kid changed across restarts: %q then %q", first.RSAKeyID, second.RSAKeyID)
	}
	if first.EncKeyID != second.EncKeyID {
		t.Errorf("encryption kid changed across restarts: %q then %q", first.EncKeyID, second.EncKeyID)
	}
	if first.HMACKeyID != second.HMACKeyID {
		t.Errorf("HMAC kid changed across restarts: %q then %q", first.HMACKeyID, second.HMACKeyID)
	}
	if first.AESKeyID != second.AESKeyID {
		t.Errorf("AES kid changed across restarts: %q then %q", first.AESKeyID, second.AESKeyID)
	}
}

// TestManagerCompletesAKeySetMissingItsAESKey covers the upgrade path: a realm
// bootstrapped before the AES key existed has three rows, and the server has to
// start rather than declare it corrupt. The other three ids must survive,
// because those are the ones a cached JWKS and every live refresh token name.
//
// The three rows are written directly rather than by generating four and
// removing one: KeyRepo has no delete, deliberately, and inventing one for a
// test would put a method in the interface that production code never calls.
func TestManagerCompletesAKeySetMissingItsAESKey(t *testing.T) {
	s, realm := newStore(t)
	ctx := context.Background()

	sigID, encID, hmacID := writeThreeKeyRows(t, s, realm.ID)

	k, err := keys.NewManager(s).ForRealm(ctx, realm)
	if err != nil {
		t.Fatalf("ForRealm: %v", err)
	}

	if k.AESKeyID == "" {
		t.Error("want an AES kid minted for the incomplete set")
	}
	if k.RSAKeyID != sigID || k.EncKeyID != encID || k.HMACKeyID != hmacID {
		t.Errorf("completing the set moved another kid: rsa %q->%q enc %q->%q hmac %q->%q",
			sigID, k.RSAKeyID, encID, k.EncKeyID, hmacID, k.HMACKeyID)
	}
	rows, err := s.Keys().ListByRealm(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListByRealm: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("want the AES row persisted, got %d rows", len(rows))
	}
	// And it survives the next restart with the id it was given, rather than
	// being minted afresh on every start.
	again, err := keys.NewManager(s).ForRealm(ctx, realm)
	if err != nil {
		t.Fatalf("second ForRealm: %v", err)
	}
	if again.AESKeyID != k.AESKeyID {
		t.Errorf("AES kid changed on the next start: %q then %q", k.AESKeyID, again.AESKeyID)
	}
}

// writeThreeKeyRows stores the key set a realm bootstrapped before the AES key
// existed would hold, and returns the three ids.
func writeThreeKeyRows(t *testing.T, s store.Store, realmID string) (sigID, encID, hmacID string) {
	t.Helper()
	ctx := context.Background()
	pkcs8 := func() []byte {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
		}
		return der
	}
	sigID, encID, hmacID = model.NewID(), model.NewID(), model.NewID()
	rows := []*model.RealmKey{
		{ID: sigID, RealmID: realmID, Algorithm: "RS256", Use: "sig",
			PrivateKey: pkcs8(), Certificate: []byte{}, CreatedAt: 1},
		{ID: encID, RealmID: realmID, Algorithm: "RSA-OAEP", Use: "enc",
			PrivateKey: pkcs8(), Certificate: []byte{}, CreatedAt: 1},
		{ID: hmacID, RealmID: realmID, Algorithm: "HS512",
			PrivateKey: []byte("secret"), Certificate: []byte{}, CreatedAt: 1},
	}
	for _, row := range rows {
		if err := s.Keys().Create(ctx, row); err != nil {
			t.Fatalf("Keys().Create(%s): %v", row.Algorithm, err)
		}
	}
	return sigID, encID, hmacID
}

func TestManagerRestoresUsableKeyMaterial(t *testing.T) {
	// The kid surviving a restart is not enough: the key bytes behind it have
	// to survive too, or a client validating against the published JWKS would
	// reject every token issued after the restart.
	s, realm := newStore(t)
	ctx := context.Background()

	first, err := keys.NewManager(s).ForRealm(ctx, realm)
	if err != nil {
		t.Fatalf("first ForRealm: %v", err)
	}
	second, err := keys.NewManager(s).ForRealm(ctx, realm)
	if err != nil {
		t.Fatalf("second ForRealm: %v", err)
	}

	firstPub := publicKey(t, first.JWKS().Keys[0])
	secondPub := publicKey(t, second.JWKS().Keys[0])
	if !firstPub.Equal(secondPub) {
		t.Error("the signing key changed across restarts even though the kid did not")
	}
	if string(first.HMACSecret()) != string(second.HMACSecret()) {
		t.Error("the HMAC secret changed across restarts; every refresh token would stop verifying")
	}
	if string(first.CertificateDER()) != string(second.CertificateDER()) {
		t.Error("the published certificate changed across restarts")
	}
}

func TestManagerIsolatesRealms(t *testing.T) {
	s, master := newStore(t)
	ctx := context.Background()
	other := &model.Realm{ID: model.NewID(), Name: "other", Enabled: true}
	if err := s.Realms().Create(ctx, other); err != nil {
		t.Fatalf("Realms().Create: %v", err)
	}
	m := keys.NewManager(s)

	a, err := m.ForRealm(ctx, master)
	if err != nil {
		t.Fatalf("ForRealm(master): %v", err)
	}
	b, err := m.ForRealm(ctx, other)
	if err != nil {
		t.Fatalf("ForRealm(other): %v", err)
	}

	if a.RSAKeyID == b.RSAKeyID {
		t.Fatal("two realms share one signing key")
	}
	if string(a.HMACSecret()) == string(b.HMACSecret()) {
		t.Fatal("two realms share one HMAC secret")
	}
}

func TestManagerPublishesSigAndEncButNotHMAC(t *testing.T) {
	s, realm := newStore(t)

	k, err := keys.NewManager(s).ForRealm(context.Background(), realm)
	if err != nil {
		t.Fatalf("ForRealm: %v", err)
	}

	set := k.JWKS()
	if len(set.Keys) != 2 {
		t.Fatalf("want 2 published keys, got %d", len(set.Keys))
	}
	byUse := map[string]string{}
	for _, key := range set.Keys {
		byUse[key.Use] = key.Algorithm
	}
	if byUse["sig"] != "RS256" || byUse["enc"] != "RSA-OAEP" {
		t.Fatalf("published algorithms wrong: %+v", byUse)
	}
	for _, key := range set.Keys {
		if key.KeyID == k.HMACKeyID {
			t.Fatal("the HMAC key is published; it signs refresh tokens and must not be")
		}
	}
}

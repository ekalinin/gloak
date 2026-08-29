package keys

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// Algorithm names as they are stored, and as the JWKS publishes them.
const (
	algRS256   = "RS256"
	algRSAOAEP = "RSA-OAEP"
	algHS512   = "HS512"
)

// Manager resolves a realm's key set, generating and persisting one the first
// time a realm is asked for. Sets are cached in memory per realm: a key is
// immutable once created, so a cached set can never go stale.
//
// Before this existed, Generate ran once per process and the one set it
// produced served every realm the router resolved - follow-up F5. The kid
// therefore changed on every restart, invalidating every cached JWKS a client
// held, and two replicas published different keys for the same realm.
type Manager struct {
	store store.Store

	mu     sync.Mutex
	cached map[string]*RealmKeys // by realm ID
}

func NewManager(s store.Store) *Manager {
	return &Manager{store: s, cached: make(map[string]*RealmKeys)}
}

// ForRealm returns realm's key set, creating it if the realm has none.
func (m *Manager) ForRealm(ctx context.Context, realm *model.Realm) (*RealmKeys, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if k, ok := m.cached[realm.ID]; ok {
		return k, nil
	}
	k, err := m.load(ctx, realm)
	if err != nil {
		return nil, err
	}
	if k == nil {
		if k, err = m.create(ctx, realm); err != nil {
			return nil, err
		}
	}
	m.cached[realm.ID] = k
	return k, nil
}

// Forget drops a realm's cached key set.
//
// A key is immutable once created, which is why the cache has no expiry - but a
// realm is not: DELETE /admin/realms/{realm} takes its keys with it through the
// schema's cascade, and a realm later created with the same id would otherwise
// be served the dead one's. Nothing else in this package invalidates anything.
func (m *Manager) Forget(realmID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cached, realmID)
}

// load rebuilds a key set from the store, or returns nil when the realm has no
// keys yet. A realm holding some but not all three is reported as corrupt
// rather than quietly completed: generating the missing key would publish a
// kid no client has ever seen while leaving the others alone.
func (m *Manager) load(ctx context.Context, realm *model.Realm) (*RealmKeys, error) {
	rows, err := m.store.Keys().ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, fmt.Errorf("keys: list realm keys: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	k := &RealmKeys{}
	for _, row := range rows {
		switch row.Algorithm {
		case algRS256:
			rsaKey, err := parseRSA(row.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("keys: signing key: %w", err)
			}
			k.RSAKeyID, k.rsaKey, k.certDER = row.ID, rsaKey, row.Certificate
		case algRSAOAEP:
			rsaKey, err := parseRSA(row.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("keys: encryption key: %w", err)
			}
			k.EncKeyID, k.encKey, k.encCertDER = row.ID, rsaKey, row.Certificate
		case algHS512:
			k.HMACKeyID, k.hmacKey = row.ID, row.PrivateKey
		}
	}
	if k.rsaKey == nil || k.encKey == nil || len(k.hmacKey) == 0 {
		return nil, fmt.Errorf("keys: realm %q has an incomplete key set", realm.Name)
	}
	return k, nil
}

func parseRSA(der []byte) (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("stored key is not RSA")
	}
	return rsaKey, nil
}

// create generates a set and persists it. A concurrent creator in another
// process is handled by the unique constraint on (realm_id, algorithm): on
// conflict the set the other process just wrote is read back, so both end up
// publishing the same kid rather than one overwriting the other.
func (m *Manager) create(ctx context.Context, realm *model.Realm) (*RealmKeys, error) {
	k, err := Generate(realm.Name)
	if err != nil {
		return nil, err
	}
	rows, err := k.rows(realm.ID, time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if err := m.store.Keys().Create(ctx, row); err != nil {
			if errors.Is(err, store.ErrConflict) {
				existing, lerr := m.load(ctx, realm)
				if lerr != nil {
					return nil, lerr
				}
				if existing == nil {
					return nil, fmt.Errorf("keys: realm %q lost its keys mid-creation", realm.Name)
				}
				return existing, nil
			}
			return nil, fmt.Errorf("keys: store realm key: %w", err)
		}
	}
	return k, nil
}

// rows encodes a generated set for storage: PKCS#8 DER for the two RSA keys,
// the raw secret for HS512. Each key ID is its row ID, so a kid read back
// after a restart is the same kid that was published before it.
func (k *RealmKeys) rows(realmID string, now int64) ([]*model.RealmKey, error) {
	sigDER, err := x509.MarshalPKCS8PrivateKey(k.rsaKey)
	if err != nil {
		return nil, fmt.Errorf("keys: encode signing key: %w", err)
	}
	encDER, err := x509.MarshalPKCS8PrivateKey(k.encKey)
	if err != nil {
		return nil, fmt.Errorf("keys: encode encryption key: %w", err)
	}
	return []*model.RealmKey{
		{ID: k.RSAKeyID, RealmID: realmID, Algorithm: algRS256, Use: "sig",
			PrivateKey: sigDER, Certificate: k.certDER, CreatedAt: now},
		{ID: k.EncKeyID, RealmID: realmID, Algorithm: algRSAOAEP, Use: "enc",
			PrivateKey: encDER, Certificate: k.encCertDER, CreatedAt: now},
		{ID: k.HMACKeyID, RealmID: realmID, Algorithm: algHS512,
			PrivateKey: k.hmacKey, Certificate: []byte{}, CreatedAt: now},
	}, nil
}

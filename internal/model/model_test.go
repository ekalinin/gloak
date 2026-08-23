package model_test

import (
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
)

func TestNewIDIsAUniqueLowercaseUUID(t *testing.T) {
	a, b := model.NewID(), model.NewID()

	if a == b {
		t.Fatalf("NewID returned the same value twice: %q", a)
	}
	if len(a) != 36 {
		t.Fatalf("want a 36-character UUID, got %d characters: %q", len(a), a)
	}
	for _, r := range a {
		if r >= 'A' && r <= 'Z' {
			t.Fatalf("want lowercase, got %q", a)
		}
	}
}

// The length and the alphabet are both measured - see NewSecret. Asserting
// them here rather than only through a golden matters because a conformance
// case has to mask the value as volatile, so nothing else can notice a secret
// that turned into 32 characters of base64.
func TestNewSecretMatchesTheMeasuredShape(t *testing.T) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	seen := map[rune]bool{}
	for range 30 {
		s := model.NewSecret()
		if len(s) != 86 {
			t.Fatalf("want an 86-character secret, got %d: %q", len(s), s)
		}
		for _, r := range s {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("character %q is outside the measured alphabet: %q", r, s)
			}
			seen[r] = true
		}
	}
	// 30 secrets is 2580 draws over 62 characters; every one appearing is
	// near-certain, and a generator stuck on a subset would show up here.
	if len(seen) != 62 {
		t.Fatalf("want all 62 characters to occur, got %d", len(seen))
	}
}

func TestNewSecretDoesNotRepeat(t *testing.T) {
	if a, b := model.NewSecret(), model.NewSecret(); a == b {
		t.Fatalf("NewSecret returned the same value twice: %q", a)
	}
}

func TestServiceAccountUsername(t *testing.T) {
	if got := model.ServiceAccountUsername("probe-secret"); got != "service-account-probe-secret" {
		t.Fatalf("want service-account-probe-secret, got %q", got)
	}
}

func TestClientCarriesKeycloakAttributes(t *testing.T) {
	// admin-cli must round-trip the lightweight access token attribute, or its
	// tokens will not match Keycloak 26.7.1. See the observed-behaviour doc.
	c := model.Client{
		ClientID:   "admin-cli",
		Attributes: map[string]string{"client.use.lightweight.access.token.enabled": "true"},
	}

	if got := c.Attributes["client.use.lightweight.access.token.enabled"]; got != "true" {
		t.Fatalf("want attribute preserved, got %q", got)
	}
}

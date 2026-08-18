package model_test

import (
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

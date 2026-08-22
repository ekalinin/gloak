package auth_test

import (
	"errors"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/ekalinin/gloak/internal/auth"
	"github.com/ekalinin/gloak/internal/model"
)

// credential builds a stored password credential the way internal/bootstrap
// does, with the argon2id parameters measured on Keycloak 26.7.1: 5
// iterations, 7168 KiB, parallelism 1, 32-byte output, values stored as arrays
// of strings. See the "Password hashing" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
func credential(password string) *model.Credential {
	salt := []byte("saltsaltsaltsalt")
	return &model.Credential{
		ID: model.NewID(), UserID: model.NewID(), Type: "password",
		Algorithm: "argon2", HashIterations: 5,
		AdditionalParameters: map[string][]string{
			"hashLength": {"32"}, "memory": {"7168"},
			"type": {"id"}, "version": {"1.3"}, "parallelism": {"1"},
		},
		Salt:      salt,
		HashValue: argon2.IDKey([]byte(password), salt, 5, 7168, 1, 32),
	}
}

func TestVerifyPasswordAcceptsTheStoredPassword(t *testing.T) {
	c := credential("admin")

	if err := auth.VerifyPassword(c, "admin"); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
}

func TestVerifyPasswordRejectsAWrongPassword(t *testing.T) {
	c := credential("admin")

	err := auth.VerifyPassword(c, "wrong-password")

	if !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("want ErrInvalidCredential, got %v", err)
	}
}

func TestVerifyPasswordRejectsAMissingCredential(t *testing.T) {
	// A user with no password must fail the same way a wrong password does.
	// Distinguishing the two would be an account-enumeration oracle.
	err := auth.VerifyPassword(nil, "admin")

	if !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("want ErrInvalidCredential, got %v", err)
	}
}

func TestVerifyPasswordReadsParametersFromTheCredential(t *testing.T) {
	// The constants in internal/bootstrap are the parameters used to *create* a
	// password. Verifying against those constants rather than against what is
	// stored would lock out every existing account the day they change.
	for _, tc := range []struct {
		name    string
		corrupt func(*model.Credential)
	}{
		{"iterations", func(c *model.Credential) { c.HashIterations = 6 }},
		{"memory", func(c *model.Credential) { c.AdditionalParameters["memory"] = []string{"8192"} }},
		{"parallelism", func(c *model.Credential) { c.AdditionalParameters["parallelism"] = []string{"2"} }},
		{"hashLength", func(c *model.Credential) { c.AdditionalParameters["hashLength"] = []string{"64"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := credential("admin")
			tc.corrupt(c)

			err := auth.VerifyPassword(c, "admin")

			if !errors.Is(err, auth.ErrInvalidCredential) {
				t.Fatalf("the %s parameter was ignored: %v", tc.name, err)
			}
		})
	}
}

func TestVerifyPasswordRejectsAnUnknownAlgorithm(t *testing.T) {
	// Not ErrInvalidCredential: "we cannot check this hash" is a different
	// answer from "this password is wrong", and a caller that mapped the two
	// together would report a configuration problem as a login failure.
	c := credential("admin")
	c.Algorithm = "pbkdf2-sha512"

	err := auth.VerifyPassword(c, "admin")

	if err == nil || errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("an unsupported algorithm must be an error of its own, got %v", err)
	}
}

func TestVerifyPasswordRejectsAnUnknownArgon2Variant(t *testing.T) {
	// Only argon2id is supported. Silently treating argon2i as argon2id would
	// compare against a hash argon2i never produced.
	c := credential("admin")
	c.AdditionalParameters["type"] = []string{"i"}

	if err := auth.VerifyPassword(c, "admin"); err == nil {
		t.Fatal("argon2i was accepted as argon2id")
	}
}

func TestVerifyPasswordRejectsAMissingParameter(t *testing.T) {
	// A silently defaulted cost parameter would verify against a hash nobody
	// produced, so an absent one is an error rather than a zero value.
	for _, name := range []string{"memory", "parallelism", "hashLength", "type"} {
		t.Run(name, func(t *testing.T) {
			c := credential("admin")
			delete(c.AdditionalParameters, name)

			if err := auth.VerifyPassword(c, "admin"); err == nil {
				t.Fatalf("a credential with no %s parameter verified anyway", name)
			}
		})
	}
}

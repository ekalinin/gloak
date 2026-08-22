// Package auth verifies stored credentials. It is deliberately separate from
// internal/bootstrap, which owns the parameters used to *create* a password:
// verification has to work with whatever is stored, including credentials
// written by an older build or imported from elsewhere. Verifying against the
// creation constants instead would lock out every existing account the day
// those constants change.
package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/argon2"

	"github.com/ekalinin/gloak/internal/model"
)

// ErrInvalidCredential means the password did not match. It is deliberately
// the same error for "wrong password" and for "no credential at all", so
// callers cannot turn the distinction into an account-enumeration oracle.
var ErrInvalidCredential = errors.New("auth: invalid credential")

// argon2idVariant is the only argon2 variant supported. Keycloak stores it as
// the "type" parameter, spelled "id".
const argon2idVariant = "id"

// VerifyPassword checks password against a stored credential, using the
// parameters recorded on the credential rather than any constant. Keycloak
// stores them as arrays of strings - see the "Password hashing" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md - which is why
// every one of them is parsed out of a []string here.
//
// A credential this function cannot evaluate - an unsupported algorithm, a
// missing cost parameter - is an error distinct from ErrInvalidCredential.
// "We cannot check this hash" is not the same answer as "this password is
// wrong", and collapsing the two would report a configuration problem as a
// login failure.
func VerifyPassword(cred *model.Credential, password string) error {
	if cred == nil {
		return ErrInvalidCredential
	}
	if cred.Algorithm != "argon2" {
		return fmt.Errorf("auth: unsupported password algorithm %q", cred.Algorithm)
	}

	variant, err := param(cred, "type")
	if err != nil {
		return err
	}
	if variant != argon2idVariant {
		return fmt.Errorf("auth: unsupported argon2 variant %q", variant)
	}
	memory, err := uintParam(cred, "memory")
	if err != nil {
		return err
	}
	parallelism, err := uintParam(cred, "parallelism")
	if err != nil {
		return err
	}
	length, err := uintParam(cred, "hashLength")
	if err != nil {
		return err
	}
	if cred.HashIterations <= 0 {
		return errors.New("auth: credential has no iteration count")
	}
	if parallelism > 255 {
		return fmt.Errorf("auth: parallelism %d does not fit argon2's 8-bit field", parallelism)
	}

	got := argon2.IDKey([]byte(password), cred.Salt,
		uint32(cred.HashIterations), memory, uint8(parallelism), length)

	// Constant time: a length check with an early return would leak the output
	// size, and a byte-by-byte comparison would leak the hash itself.
	// ConstantTimeCompare already returns 0 for differing lengths.
	if subtle.ConstantTimeCompare(got, cred.HashValue) != 1 {
		return ErrInvalidCredential
	}
	return nil
}

// param returns the single value of a credential parameter. An absent or empty
// parameter is an error rather than a zero value: verifying with a silently
// defaulted cost parameter would compare against a hash nobody produced.
func param(cred *model.Credential, name string) (string, error) {
	values := cred.AdditionalParameters[name]
	if len(values) == 0 {
		return "", fmt.Errorf("auth: credential has no %s parameter", name)
	}
	return values[0], nil
}

func uintParam(cred *model.Credential, name string) (uint32, error) {
	raw, err := param(cred, name)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("auth: %s parameter %q is not a number: %w", name, raw, err)
	}
	return uint32(v), nil
}

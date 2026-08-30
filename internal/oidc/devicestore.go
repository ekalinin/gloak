package oidc

import (
	"crypto/rand"
	"sync"
	"time"
)

// A device code lives in memory, beside the authentication session and the
// authorization code, and for the same reason: Keycloak keeps all three in
// Infinispan rather than in its schema, because all three are short-lived.
//
// It carries the same cost the other two carry - **this is single-process**, so
// two Gloak replicas will not share a device authorization in flight. See
// follow-up F75, which this extends rather than repeats.

// deviceCodeBytes makes a 43-character base64url device_code. Measured over
// sixty mints: every device_code was 43 characters and the alphabet was exactly
// base64url's 64, so it is 32 random bytes unpadded.
const deviceCodeBytes = 32

// userCodeAlphabet and userCodeGroup are the measured shape of user_code:
// XXXX-XXXX, nine characters, upper-case ASCII letters only.
//
// The alphabet is measured rather than assumed. Sixty mints produced 480 code
// characters and every one of the 26 letters appeared; **no digit ever did**,
// which is what rules out the obvious guess of an alphanumeric alphabet - with
// 36 symbols the chance of 480 draws avoiding all ten digits is about e^-156.
const (
	userCodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	userCodeGroup    = 4
)

// deviceCodeGrace is how long past its expiry a device code keeps answering
// expired_token before it stops being found at all.
//
// **The window is measured and its size is not pinned.** An expired code does
// not answer expired_token for ever: at three client lifespans, the answer
// turns into "Device code not valid" some seconds after the expiry, which is
// the same answer a code that never existed gets.
//
//	lifespan  last expired_token   first "not valid"
//	       1   mint+16s (+15s)      mint+17s (+16s)
//	       5   mint+18s (+13s)      mint+21s (+16s)
//	      20   mint+30s (+10s)      mint+35s (+15s)
//
// Fifteen seconds is inside every one of those brackets and no formula fits all
// three tighter than that; the boundary reproduced exactly across two runs at
// one-second granularity for lifespan 1. **No mechanism for the number has been
// found**, so it is a measured approximation rather than an understanding, and
// it is filed as a follow-up rather than written down as though it were exact.
//
// The two extremes are both wrong and both are what an implementation reaches
// for. Sweeping at expiry answers "Device code not valid" where Keycloak
// answers expired_token, which is the case this cut records. Never sweeping
// answers expired_token for ever, which is a leak as well as a divergence.
const deviceCodeGrace = 15 * time.Second

// deviceCode is one device authorization request in flight.
//
// UserID is empty until somebody approves it, which is what makes
// authorization_pending the default answer. Denied is a third state rather than
// a missing UserID, because a denied code answers access_denied for as long as
// it lives and is measurably **not** consumed by the poll that reports it.
type deviceCode struct {
	Code       string
	UserCode   string
	Realm      string
	ClientUUID string
	Scope      string
	Interval   time.Duration
	ExpiresAt  time.Time

	// LastPoll is when this code was last polled by a caller that got past the
	// client check. It is zero until the first such poll, which is why the
	// first poll is never slow_down.
	//
	// Measured: a slow_down does **not** move it. Polls at t=0, t=3 and t=6
	// with interval 5 answered pending, slow_down, pending - where an
	// implementation that stamped every poll would answer slow_down at t=6.
	LastPoll time.Time

	Denied    bool
	UserID    string
	SessionID string
}

// deviceStore holds every device code this process has minted, keyed by the
// device_code and by the user_code.
//
// Two maps rather than one plus a scan: the user_code is what the verification
// page will look a code up by in cut B, and a linear scan over codes in flight
// is the kind of thing that is fine until it is not.
//
// Expired entries are swept on write, never on a read, which is authStore's
// rule and is repeated here rather than shared because the two hold different
// things with different lifetimes.
type deviceStore struct {
	mu        sync.Mutex
	codes     map[string]*deviceCode
	userCodes map[string]*deviceCode
	now       func() time.Time
}

func newDeviceStore() *deviceStore {
	return &deviceStore{
		codes:     map[string]*deviceCode{},
		userCodes: map[string]*deviceCode{},
		now:       time.Now,
	}
}

// newDeviceCode mints the pair and stores what polling it will need. The caller
// supplies everything except the two identifiers and the expiry.
func (s *deviceStore) newDeviceCode(dc *deviceCode, lifespan time.Duration) (*deviceCode, error) {
	code, err := randomBase64URL(deviceCodeBytes)
	if err != nil {
		return nil, err
	}
	userCode, err := randomUserCode()
	if err != nil {
		return nil, err
	}
	dc.Code = code
	dc.UserCode = userCode
	dc.ExpiresAt = s.now().Add(lifespan)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	s.codes[code] = dc
	s.userCodes[userCode] = dc
	return dc, nil
}

// deviceCodeByCode resolves a device_code without spending it, because most of
// the measured answers leave it in place: authorization_pending, slow_down,
// access_denied and expired_token are all repeatable on the same code.
//
// It reports false for a code of another realm, exactly as spendCode does, so
// that a code cannot be redeemed across a realm boundary by a caller that has
// somehow seen it.
func (s *deviceStore) deviceCodeByCode(realm, code string) (*deviceCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, ok := s.codes[code]
	if !ok || dc.Realm != realm {
		return nil, false
	}
	return dc, true
}

// deviceCodeByUserCode resolves a code by the nine characters a person typed or
// followed, which is the only identifier the browser half ever sees.
//
// An expired code reports false here where deviceCodeByCode still finds one, and
// the difference is measured on the two sides: the poll answers expired_token
// for about fifteen seconds past the expiry, and the verification page answers
// "Invalid code, please try again." - the same thing an unknown code gets. So
// the grace window is the poll's and not the page's.
func (s *deviceStore) deviceCodeByUserCode(realm, userCode string) (*deviceCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, ok := s.userCodes[userCode]
	if !ok || dc.Realm != realm || s.now().After(dc.ExpiresAt) {
		return nil, false
	}
	return dc, true
}

// approveDeviceCode and denyDeviceCode are the two ways a device authorization
// leaves the pending state. Both are keyed by the **user_code**, because that is
// what the person at the browser typed in and the only identifier the
// verification page ever sees - the device_code never leaves the device.
//
// They report whether anything was found, so a verification page can tell an
// unknown or expired user code from one it moved.
//
// A denial does not delete the code. Measured: a denied code answered
// access_denied on every later poll rather than becoming "not valid", which is
// what distinguishes it from a code that was successfully redeemed.
func (s *deviceStore) approveDeviceCode(userCode, userID, sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, ok := s.userCodes[userCode]
	if !ok || s.now().After(dc.ExpiresAt) {
		return false
	}
	dc.UserID = userID
	dc.SessionID = sessionID
	return true
}

func (s *deviceStore) denyDeviceCode(userCode string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, ok := s.userCodes[userCode]
	if !ok || s.now().After(dc.ExpiresAt) {
		return false
	}
	dc.Denied = true
	return true
}

// stampPoll records that a poll got as far as being answered about the code's
// own state, which is what the interval is measured from.
//
// It is a separate call rather than a side effect of the lookup because the two
// checks that run in front of it - expiry and the client match - measurably do
// not move the clock.
func (s *deviceStore) stampPoll(dc *deviceCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dc.LastPoll = s.now()
}

// spendDeviceCode removes a code, which happens on exactly one path: a
// successful exchange. Measured, the poll after a success answers "Device code
// not valid", so a spent code is indistinguishable from one that never existed.
func (s *deviceStore) spendDeviceCode(dc *deviceCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, dc.Code)
	delete(s.userCodes, dc.UserCode)
}

// sweepLocked drops codes that are past their expiry *and* past the grace
// window above, so an expired code still answers expired_token for as long as
// Keycloak's does.
func (s *deviceStore) sweepLocked() {
	cutoff := s.now().Add(-deviceCodeGrace)
	for code, dc := range s.codes {
		if cutoff.After(dc.ExpiresAt) {
			delete(s.codes, code)
			delete(s.userCodes, dc.UserCode)
		}
	}
}

// randomUserCode builds the measured XXXX-XXXX shape.
//
// The draw is rejection-free because 26 does not divide 256 evenly and a plain
// modulo would bias the first four letters. crypto/rand.Text is not used: it
// emits its own base32 alphabet, which is not this one.
func randomUserCode() (string, error) {
	const letters = 2 * userCodeGroup
	out := make([]byte, 0, letters+1)
	buf := make([]byte, 1)
	for len(out) < letters+1 {
		if len(out) == userCodeGroup {
			out = append(out, '-')
			continue
		}
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		// Reject the tail that would bias the alphabet rather than folding it
		// in: 256 is not a multiple of 26, so the first 256 % 26 letters would
		// otherwise come up more often than the rest.
		if int(buf[0]) >= (256/len(userCodeAlphabet))*len(userCodeAlphabet) {
			continue
		}
		out = append(out, userCodeAlphabet[int(buf[0])%len(userCodeAlphabet)])
	}
	return string(out), nil
}

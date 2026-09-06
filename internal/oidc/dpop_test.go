package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ekalinin/gloak/internal/model"
)

// The five behaviours below are DPoP's and **no golden can hold any of them**,
// which is why they are here rather than in the catalogue:
//
//   - a header present and empty, which a Case's Headers map cannot express
//     distinctly from one it does not set;
//   - a JOSE header with no typ at all, which the fixture's Proof either
//     spells or defaults;
//   - a proof sent twice, which needs one request repeated;
//   - an htu carrying a query, whose acceptance is invisible in a 200 that
//     looks like every other 200;
//   - the binding itself, which lives inside tokens every golden masks.

const dpopTestPath = "/realms/master/protocol/openid-connect/token"

// dpopTestKey is a P-256 private scalar, fixed so that a test can assert a
// thumbprint without computing it twice from the same code.
const dpopTestKey = "36b2a9616df68459e8b6de63acbb7a60f27644364d9423f8af1a25fae5ae80a8"

// dpopTestJkt is dpopTestKey's RFC 7638 thumbprint, measured by sending a proof
// signed with it to a live 26.7.1 and reading cnf.jkt out of the token.
const dpopTestJkt = "M4Jn94Dhies0pdHfQUCmEWSdr8IoTXCr_Td6HAHywSE"

// testProof signs a proof over the fixed key. header and claims are given as
// maps so that a test can leave a field out, which is the whole point of two of
// the cases below.
func testProof(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	curve := elliptic.P256()
	d, ok := new(big.Int).SetString(dpopTestKey, 16)
	if !ok {
		t.Fatal("dpopTestKey is not hex")
	}
	x, y := curve.ScalarBaseMult(d.Bytes())
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}

	if _, set := header["jwk"]; !set {
		xb, yb := make([]byte, 32), make([]byte, 32)
		key.X.FillBytes(xb)
		key.Y.FillBytes(yb)
		header["jwk"] = map[string]string{
			"crv": "P-256", "kty": "EC",
			"x": base64.RawURLEncoding.EncodeToString(xb),
			"y": base64.RawURLEncoding.EncodeToString(yb),
		}
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signing := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// validProof is the control every test here varies from: the typ, the alg, the
// jwk and all four claims, aimed at this handler's own token endpoint.
func validProof(t *testing.T) string {
	t.Helper()
	return testProof(t,
		map[string]any{"typ": "dpop+jwt", "alg": "ES256"},
		map[string]any{
			"htm": http.MethodPost,
			"htu": "http://localhost:8080" + dpopTestPath,
			"iat": time.Now().Unix(),
			"jti": freshJTI(t),
		})
}

func freshJTI(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("jti: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// postWithDPoP sends the password grant, optionally carrying a DPoP header.
// A nil proof means no header at all, which is not the same request as one
// carrying an empty header - that difference is what the first test is about.
func postWithDPoP(t *testing.T, h http.Handler, proof *string) *httptest.ResponseRecorder {
	t.Helper()
	form := passwordGrantForm("")
	req := httptest.NewRequest(http.MethodPost, dpopTestPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != nil {
		req.Header.Set("DPoP", *proof)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func dpopDescription(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse error body %q: %v", w.Body, err)
	}
	return body.Description
}

// TestDPoPHeaderPresentAndEmptyIsRefusedWhereNoHeaderIsNot is the surprise, and
// the control is the first row: admin-cli requires nothing, so the same request
// without the header answers 200 with an ordinary Bearer token.
//
// It was measured by sending the bytes explicitly, because curl drops a header
// written -H "Name:  " rather than sending an empty one - and the 200 that
// spelling produced was curl's answer, not Keycloak's.
func TestDPoPHeaderPresentAndEmptyIsRefusedWhereNoHeaderIsNot(t *testing.T) {
	h, s, _ := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)

	absent := postWithDPoP(t, router, nil)
	if absent.Code != http.StatusOK {
		t.Fatalf("no DPoP header: want 200, got %d: %s", absent.Code, absent.Body)
	}
	if got := decodeTokenResponse(t, absent).TokenType; got != "Bearer" {
		t.Errorf("no DPoP header: token_type %q, want Bearer", got)
	}

	for _, value := range []string{"", " ", "   ", "\t"} {
		w := postWithDPoP(t, router, &value)
		if w.Code != http.StatusBadRequest {
			t.Errorf("DPoP header %q: want 400, got %d: %s", value, w.Code, w.Body)
			continue
		}
		if got := dpopDescription(t, w); got != descDPoPMissing {
			t.Errorf("DPoP header %q: got %q, want %q", value, got, descDPoPMissing)
		}
	}
}

// TestDPoPProofWithNoTypeNamesNull pins the interpolation of a claim that is
// not there. An absent typ spells the literal word "null" and an empty one
// spells nothing, so the two are not one message written twice.
func TestDPoPProofWithNoTypeNamesNull(t *testing.T) {
	h, s, _ := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)

	for _, tc := range []struct {
		name   string
		header map[string]any
		want   string
	}{
		{"absent", map[string]any{"alg": "ES256"},
			"Invalid or missing type in DPoP header: null"},
		{"empty", map[string]any{"alg": "ES256", "typ": ""},
			"Invalid or missing type in DPoP header: "},
		{"uppercase", map[string]any{"alg": "ES256", "typ": "DPOP+JWT"},
			"Invalid or missing type in DPoP header: DPOP+JWT"},
	} {
		proof := testProof(t, tc.header, map[string]any{
			"htm": http.MethodPost,
			"htu": "http://localhost:8080" + dpopTestPath,
			"iat": time.Now().Unix(),
			"jti": freshJTI(t),
		})
		w := postWithDPoP(t, router, &proof)
		if got := dpopDescription(t, w); got != tc.want {
			t.Errorf("typ %s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestDPoPProofCannotBeReplayed is the half of the reason that survived: the
// jti is single-use, so no literal in the catalogue could ever be sent twice.
// The first request is the control and has to succeed.
func TestDPoPProofCannotBeReplayed(t *testing.T) {
	h, s, _ := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)

	proof := validProof(t)
	first := postWithDPoP(t, router, &proof)
	if first.Code != http.StatusOK {
		t.Fatalf("first use: want 200, got %d: %s", first.Code, first.Body)
	}
	second := postWithDPoP(t, router, &proof)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("second use: want 400, got %d: %s", second.Code, second.Body)
	}
	if got := dpopDescription(t, second); got != descDPoPReplayed {
		t.Errorf("second use: got %q, want %q", got, descDPoPReplayed)
	}
}

// TestDPoPHtuIgnoresTheQueryAndNothingElse is invisible in a golden: a proof
// whose htu carries a query is accepted and answers the same 200 as one that
// does not, while a proof naming another path is refused.
func TestDPoPHtuIgnoresTheQueryAndNothingElse(t *testing.T) {
	h, s, _ := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)

	for _, tc := range []struct {
		htu  string
		want int
	}{
		{"http://localhost:8080" + dpopTestPath, http.StatusOK},
		{"http://localhost:8080" + dpopTestPath + "?x=1", http.StatusOK},
		{"http://localhost:8080" + dpopTestPath + "#frag", http.StatusOK},
		{"http://localhost:8080" + dpopTestPath + "x", http.StatusBadRequest},
		{"http://localhost:9999" + dpopTestPath, http.StatusBadRequest},
	} {
		proof := testProof(t,
			map[string]any{"typ": "dpop+jwt", "alg": "ES256"},
			map[string]any{
				"htm": http.MethodPost,
				"htu": tc.htu,
				"iat": time.Now().Unix(),
				"jti": freshJTI(t),
			})
		w := postWithDPoP(t, router, &proof)
		if w.Code != tc.want {
			t.Errorf("htu %q: want %d, got %d: %s", tc.htu, tc.want, w.Code, w.Body)
		}
	}
}

// TestDPoPBindsTheAccessAndRefreshTokensAndNotTheID is what the goldens cannot
// see. Every token in the bound-token golden is masked to {{string}}, so a
// handler that answered token_type DPoP and bound nothing would match it byte
// for byte.
//
// It asserts the position as well as the value: cnf sits immediately before
// scope, measured on a lightweight client and a full one alike.
func TestDPoPBindsTheAccessAndRefreshTokensAndNotTheID(t *testing.T) {
	h, s, _ := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)

	form := passwordGrantForm("openid")
	req := httptest.NewRequest(http.MethodPost, dpopTestPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	proof := validProof(t)
	req.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	body := decodeTokenResponse(t, w)
	if body.TokenType != "DPoP" {
		t.Errorf("token_type %q, want DPoP", body.TokenType)
	}
	for _, tc := range []struct {
		name  string
		token string
	}{{"access_token", body.AccessToken}, {"refresh_token", body.RefreshToken}} {
		keys, claims := claimOrder(t, tc.token)
		cnf, ok := claims["cnf"].(map[string]any)
		if !ok {
			t.Errorf("%s: no cnf, got keys %v", tc.name, keys)
			continue
		}
		if cnf["jkt"] != dpopTestJkt {
			t.Errorf("%s: cnf.jkt %v, want %s", tc.name, cnf["jkt"], dpopTestJkt)
		}
		if cnf["kc-jkt-type"] != "DPoP" {
			t.Errorf("%s: cnf.kc-jkt-type %v, want DPoP", tc.name, cnf["kc-jkt-type"])
		}
		next := indexOf(keys, "cnf") + 1
		if next <= 0 || next >= len(keys) || keys[next] != "scope" {
			t.Errorf("%s: cnf is not immediately before scope, order %v", tc.name, keys)
		}
	}
	idKeys, idClaims := claimOrder(t, body.IDToken)
	if _, ok := idClaims["cnf"]; ok {
		t.Errorf("the ID token carries cnf, and no measured one does: %v", idKeys)
	}
}

// claimOrder decodes a JWT's payload, returning its keys in the order they were
// serialised and the claims themselves. The order matters: this project
// reproduces Keycloak's key order and encoding/json sorts a map's.
func claimOrder(t *testing.T, raw string) ([]string, map[string]any) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse payload: %v", err)
	}

	dec := json.NewDecoder(strings.NewReader(string(payload)))
	if _, err := dec.Token(); err != nil {
		t.Fatalf("read object start: %v", err)
	}
	var order []string
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		order = append(order, key.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil && err != io.EOF {
			t.Fatalf("skip value: %v", err)
		}
	}
	return order, claims
}

func indexOf(values []string, want string) int {
	for i, v := range values {
		if v == want {
			return i
		}
	}
	return -1
}

// TestDPoPIsCheckedAfterTheDuplicateParameterAndBeforeTheGrant pins the two
// adjacencies either side of the proof, each by a request that is wrong in two
// ways. No golden can: a Case sends one request and the answer to a request
// wrong in one way says nothing about the order.
func TestDPoPIsCheckedAfterTheDuplicateParameterAndBeforeTheGrant(t *testing.T) {
	h, s, _ := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)

	send := func(form url.Values) string {
		req := httptest.NewRequest(http.MethodPost, dpopTestPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", "not-a-proof")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return dpopDescription(t, w)
	}

	duplicated := passwordGrantForm("")
	duplicated["zz"] = []string{"1", "2"}
	if got := send(duplicated); got != descDuplicatedParameter {
		t.Errorf("a bad proof with a duplicated key: got %q, want %q", got, descDuplicatedParameter)
	}

	wrongPassword := passwordGrantForm("")
	wrongPassword.Set("password", "gloak-probe-wrong")
	if got := send(wrongPassword); got != descDPoPHeaderFailure {
		t.Errorf("a bad proof with a wrong password: got %q, want %q", got, descDPoPHeaderFailure)
	}

	// The control: without the header the same two requests answer about the
	// other fault, so neither row above is measuring the endpoint refusing
	// everything.
	if got := postForm(t, router, dpopTestPath, wrongPassword).Code; got != http.StatusBadRequest {
		t.Errorf("control: a wrong password with no proof got %d", got)
	}
}

// TestDPoPComparesTheURLBeforeTheMethod is the other adjacency, and it needs a
// proof wrong about both. A proof wrong about one says nothing.
func TestDPoPComparesTheURLBeforeTheMethod(t *testing.T) {
	h, s, _ := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)

	both := testProof(t,
		map[string]any{"typ": "dpop+jwt", "alg": "ES256"},
		map[string]any{
			"htm": http.MethodGet,
			"htu": "http://localhost:8080/realms/master/protocol/openid-connect/userinfo",
			"iat": time.Now().Unix(),
			"jti": freshJTI(t),
		})
	w := postWithDPoP(t, router, &both)
	if got := dpopDescription(t, w); got != descDPoPURLMismatch {
		t.Errorf("wrong about both: got %q, want %q", got, descDPoPURLMismatch)
	}

	// The control: the same proof with the URL put right answers about the
	// method, so the row above is an ordering and not a preference for one
	// sentence.
	methodOnly := testProof(t,
		map[string]any{"typ": "dpop+jwt", "alg": "ES256"},
		map[string]any{
			"htm": http.MethodGet,
			"htu": "http://localhost:8080" + dpopTestPath,
			"iat": time.Now().Unix(),
			"jti": freshJTI(t),
		})
	w = postWithDPoP(t, router, &methodOnly)
	if got := dpopDescription(t, w); got != descDPoPMethodMismatch {
		t.Errorf("wrong about the method alone: got %q, want %q", got, descDPoPMethodMismatch)
	}
}

// TestDPoPIatWindowIsAsymmetric pins both edges. The golden for
// dpop-proof-not-active is thirty seconds old and would still be refused by a
// window half that size, so the numbers themselves are unasserted without this.
//
// [now-25, now+15], measured at one second's resolution against a container
// whose clock agreed with the host's.
func TestDPoPIatWindowIsAsymmetric(t *testing.T) {
	h, s, _ := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)

	for _, tc := range []struct {
		offset time.Duration
		want   int
	}{
		{-24 * time.Second, http.StatusOK},
		{-26 * time.Second, http.StatusBadRequest},
		{14 * time.Second, http.StatusOK},
		{16 * time.Second, http.StatusBadRequest},
	} {
		proof := testProof(t,
			map[string]any{"typ": "dpop+jwt", "alg": "ES256"},
			map[string]any{
				"htm": http.MethodPost,
				"htu": "http://localhost:8080" + dpopTestPath,
				"iat": time.Now().Add(tc.offset).Unix(),
				"jti": freshJTI(t),
			})
		w := postWithDPoP(t, router, &proof)
		if w.Code != tc.want {
			t.Errorf("iat %+v: want %d, got %d: %s", tc.offset, tc.want, w.Code, w.Body)
		}
	}
}

// TestDPoPBindsAFullAccessTokenInTheSamePlace is the other claim set. Every
// other test here uses admin-cli, which is a **lightweight** client - so a
// mutation moving cnf on the full access token survived the whole suite until
// this test existed, and the position was measured on both.
func TestDPoPBindsAFullAccessTokenInTheSamePlace(t *testing.T) {
	h, s, realm := newHandler(t)
	full := &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: "gloak-probe-dpop-full",
		Enabled: true, PublicClient: true, DirectAccessGrantsEnabled: true,
	}
	if err := s.Clients().Create(context.Background(), full); err != nil {
		t.Fatalf("Clients().Create: %v", err)
	}
	router := NewRouter(s, h.keys, h.issuerBase)

	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"gloak-probe-dpop-full"},
		"username":   {"admin"},
		"password":   {"admin"},
	}
	req := httptest.NewRequest(http.MethodPost, dpopTestPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	proof := validProof(t)
	req.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	body := decodeTokenResponse(t, w)
	keys, claims := claimOrder(t, body.AccessToken)
	if _, lightweight := claims["sub"]; !lightweight {
		t.Fatalf("this client's access token has no sub, so it is the lightweight set: %v", keys)
	}
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("the full access token carries no cnf: %v", keys)
	}
	if cnf["jkt"] != dpopTestJkt {
		t.Errorf("cnf.jkt %v, want %s", cnf["jkt"], dpopTestJkt)
	}
	next := indexOf(keys, "cnf") + 1
	if next <= 0 || next >= len(keys) || keys[next] != "scope" {
		t.Errorf("cnf is not immediately before scope, order %v", keys)
	}
}

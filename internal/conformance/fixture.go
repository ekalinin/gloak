package conformance

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// Step is one request run before a case's own, whose response contributes
// values the case can refer to. Steps are never recorded as goldens: only the
// case's own response is. Recording them would commit a live token to the
// repository.
type Step struct {
	Request Request
	// Capture maps a variable name to a slash-separated path into the step's
	// JSON response body. "access_token" is the common one.
	Capture map[string]string
	// CaptureHeader maps a variable name to a response header. The admin API
	// answers a create with 201, an empty body and the new object's URL in
	// Location, so there is nothing for Capture to read; this is how a case
	// gets hold of an identifier the server minted.
	//
	// A value that parses as a URL yields its final path segment, since that
	// is what a case substitutes into a path and the base URL differs between
	// the recorder and the verifier. Anything else is captured whole.
	CaptureHeader map[string]string
}

// Fixture is the setup a case runs against: a named server-side starting
// state, plus the steps that lead from it to the state the case measures.
type Fixture struct {
	// State names the starting point. "bootstrap" is a fresh master realm,
	// and is the only one today.
	State string
	Steps []Step
}

// Fixtures is every setup a case may name. One declaration, executed twice:
// by the recorder against the reference container and by the verifier against
// the in-process handler. Two declarations would compare responses obtained
// in different ways, which is the one thing this suite cannot afford.
var Fixtures = map[string]Fixture{
	"bootstrap": {State: "bootstrap"},

	// admin-token holds an access token and a refresh token for the
	// bootstrapped administrator, obtained the way kcadm.sh obtains one: the
	// password grant on admin-cli.
	//
	// Note that admin-cli is a lightweight client, so the access token this
	// yields carries no sub, aud or realm_access - see the "Lightweight
	// access tokens" section of
	// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
	"admin-token": {
		State: "bootstrap",
		Steps: []Step{{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/realms/master/protocol/openid-connect/token",
				Form: map[string]string{
					"grant_type": "password",
					"client_id":  "admin-cli",
					"username":   "admin",
					"password":   "admin",
				},
			},
			Capture: map[string]string{
				"access_token":  "access_token",
				"refresh_token": "refresh_token",
			},
		}},
	},

	// admin-token-openid is admin-token with the openid scope requested.
	//
	// The two differ in exactly one way and it is not cosmetic: a token
	// obtained without openid is refused by the userinfo endpoint, measured
	// as 403 with WWW-Authenticate carrying error="insufficient_scope" and
	// error_description="Missing openid scope". A case measuring what
	// userinfo returns for a valid token needs this fixture; a case
	// measuring the token endpoint's own response needs admin-token, whose
	// recorded scope is "email profile" precisely because it did not ask for
	// openid.
	"admin-token-openid": {
		State: "bootstrap",
		Steps: []Step{{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/realms/master/protocol/openid-connect/token",
				Form: map[string]string{
					"grant_type": "password",
					"client_id":  "admin-cli",
					"username":   "admin",
					"password":   "admin",
					"scope":      "openid",
				},
			},
			Capture: map[string]string{
				"access_token":  "access_token",
				"refresh_token": "refresh_token",
			},
		}},
	},
}

// Do performs one request. The recorder's implementation talks to the
// reference container over HTTP; the verifier's serves the in-process handler
// through httptest. Both return the response with its body still readable.
type Do func(*http.Request) (*http.Response, error)

// RunFixture executes a fixture's steps in order against do, threading the
// values each step captures into the requests that follow, and returns
// everything captured.
//
// A step whose response lacks a captured path is an error, not an empty
// string. Substituting an empty token would record whatever Keycloak answers
// for a blank credential: a real response to a request nobody meant to make,
// and one that would look like a measured contract afterwards.
func RunFixture(f Fixture, base string, do Do) (map[string]string, error) {
	vars := map[string]string{}
	for i, s := range f.Steps {
		req, err := buildRequest(base, Expand(s.Request, vars))
		if err != nil {
			return nil, fmt.Errorf("fixture step %d: build request: %w", i, err)
		}
		resp, err := do(req)
		if err != nil {
			return nil, fmt.Errorf("fixture step %d: %w", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("fixture step %d: read body: %w", i, err)
		}
		for name, path := range s.Capture {
			value, err := captureFrom(body, path)
			if err != nil {
				return nil, fmt.Errorf("fixture step %d: capture %q: %w (status %d, body %s)",
					i, name, err, resp.StatusCode, body)
			}
			vars[name] = value
		}
		for name, header := range s.CaptureHeader {
			value, err := captureFromHeader(resp.Header, header)
			if err != nil {
				return nil, fmt.Errorf("fixture step %d: capture %q: %w (status %d)",
					i, name, err, resp.StatusCode)
			}
			vars[name] = value
		}
	}
	return vars, nil
}

// captureFrom pulls one value out of a JSON body by slash-separated path.
//
// Unlike the golden comparison passes this unmarshals rather than splicing
// bytes: a captured value is fed back into a request, never written to a
// golden, so key order does not matter here.
func captureFrom(body []byte, path string) (string, error) {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("response is not JSON: %w", err)
	}
	cur := doc
	for seg := range strings.SplitSeq(path, "/") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("path %q: %q is not reachable, parent is not an object", path, seg)
		}
		cur, ok = obj[seg]
		if !ok {
			return "", fmt.Errorf("path %q: no key %q", path, seg)
		}
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("path %q: value is %T, not a string", path, cur)
	}
	return s, nil
}

// captureFromHeader pulls one value out of a response header.
//
// An absent header is an error rather than an empty string, for the same
// reason a missing body capture is: substituting nothing would turn
// ".../clients/{{client_uuid}}" into ".../clients/" and record whatever that
// answers as though somebody had meant to ask for it.
//
// A value that parses as an absolute URL yields its last path segment. That is
// what Location carries and what a case needs, and taking it here rather than
// in every case keeps the base URL - which differs between the recorder and
// the verifier - out of the catalogue.
func captureFromHeader(h http.Header, name string) (string, error) {
	value := h.Get(name)
	if value == "" {
		return "", fmt.Errorf("response has no %s header", name)
	}
	if u, err := url.Parse(value); err == nil && u.IsAbs() {
		if segment := path.Base(u.Path); segment != "." && segment != "/" {
			return segment, nil
		}
	}
	return value, nil
}

// Expand substitutes {{name}} references in a request's query, headers and
// form values with captured variables. A reference with no matching variable
// is left alone, so a typo shows up in the recorded request rather than
// silently becoming an empty string.
//
// It copies every map it touches. One Case is expanded twice - once by the
// recorder with the container's tokens, once by the verifier with Gloak's -
// so writing through to the catalogue's own maps would let the first run
// poison the second.
func Expand(r Request, vars map[string]string) Request {
	out := r
	out.Query = expandMap(r.Query, vars)
	out.Headers = expandMap(r.Headers, vars)
	out.Form = expandMap(r.Form, vars)
	return out
}

func expandMap(in, vars map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		for name, value := range vars {
			v = strings.ReplaceAll(v, "{{"+name+"}}", value)
		}
		out[k] = v
	}
	return out
}

// ReplaceCaptured masks captured values wherever they appear in a recorded
// response, using the same {{name}} spelling the request used to refer to
// them.
//
// Without it a golden for an endpoint that echoes its input - introspection
// is the obvious one - would hold a live token, and would therefore differ
// from itself on every recording. That is the churn four goldens already
// have, and it is what stops a `make record` diff from being read.
//
// An empty value is skipped: strings.ReplaceAll with an empty old string
// inserts the replacement between every byte of the input.
func ReplaceCaptured(raw []byte, vars map[string]string) []byte {
	for name, value := range vars {
		if value == "" {
			continue
		}
		raw = []byte(strings.ReplaceAll(string(raw), value, "{{"+name+"}}"))
	}
	return raw
}

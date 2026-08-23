package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// openapiPath is Keycloak's own description of its Admin REST API, vendored
// rather than fetched so that `go test ./...` keeps needing neither Docker nor
// network.
//
// It supplies the parity denominator and nothing else. This is the same split
// the rest of the suite runs on - the documentation says which behaviours
// exist, a running Keycloak says what they emit - applied one level up. Not
// one expected byte comes from this file, only the names of operations that
// exist.
//
// Retargeting to another Keycloak version means committing that version's file
// alongside this one and repointing this constant, then re-recording every
// golden against the new container. The old file stays: it is the record of
// what parity was being measured against before.
const openapiPath = "testdata/openapi/keycloak-26.7.1.json"

// untaggedTag stands for operations the description gives no tag. In 26.7.1
// all 31 of them are under
// /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server: they are
// Authorization Services.
const untaggedTag = "(untagged)"

// httpMethods are the keys of a path item that describe an operation. A path
// item also holds "parameters", "summary" and "$ref", which are not
// operations and must not be counted as surface.
//
// The non-operation keys are not merely uninteresting, they are shaped
// differently: "parameters" holds an array where an operation holds an
// object. That is why the path item is decoded one raw value at a time and
// filtered by key before anything tries to read tags out of it.
var httpMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"patch": true, "options": true, "head": true,
}

// Operations returns every operation the vendored description carries, keyed
// "METHOD path" exactly as the document spells the path - for example
// "GET /admin/realms/{realm}/clients".
//
// The key is method and path rather than an operationId because **the
// description carries no operationId at all**: zero of its 413 operations have
// one, and the fields an operation does have are description, parameters,
// responses, summary and tags. TestNoOperationCarriesAnOperationID pins that,
// so a future vendored version that does carry them fails loudly instead of
// letting this choice drift unexamined.
//
// Method and path together are unique within the document, come from outside
// this project, and are checkable - which is the whole requirement for a
// parity key. See section 5 of
// docs/superpowers/specs/2026-08-22-p2-admin-api-core-design.md.
func Operations() (map[string]bool, error) {
	doc, err := readDescription()
	if err != nil {
		return nil, err
	}
	ops := make(map[string]bool)
	for path, item := range doc {
		for method := range item {
			if !httpMethods[method] {
				continue
			}
			ops[strings.ToUpper(method)+" "+path] = true
		}
	}
	return ops, nil
}

// readDescription decodes the vendored file's paths one raw value at a time,
// which is what lets callers filter by HTTP method before anything tries to
// read an operation's fields. A path item's "parameters" key holds an array
// where an operation holds an object, so decoding the whole item as operations
// fails outright.
func readDescription() (map[string]map[string]json.RawMessage, error) {
	raw, err := os.ReadFile(filepath.FromSlash(openapiPath))
	if err != nil {
		return nil, fmt.Errorf("conformance: read openapi description: %w", err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("conformance: parse openapi description: %w", err)
	}
	return doc.Paths, nil
}

// servedOperations counts the distinct operations that have at least one
// Implemented case.
//
// Distinct is the point. A chapter's denominator is an operation count, so
// counting cases would report "3 of 34 served" for one endpoint with a
// success, a 404 and a 403 case - overcounting hardest exactly where the error
// handling is most careful, and rewarding writing more cases for an endpoint
// already served.
func servedOperations(cases []Case) int {
	seen := map[string]bool{}
	for _, c := range cases {
		if c.Status == Implemented && c.Operation != "" {
			seen[c.Operation] = true
		}
	}
	return len(seen)
}

// OperationsByTag counts the operations the vendored description carries
// under each tag. An operation with several tags counts under each of them,
// which is how the description itself presents them.
func OperationsByTag() (map[string]int, error) {
	raw, err := os.ReadFile(filepath.FromSlash(openapiPath))
	if err != nil {
		return nil, fmt.Errorf("conformance: read openapi description: %w", err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("conformance: parse openapi description: %w", err)
	}

	byTag := map[string]int{}
	for path, item := range doc.Paths {
		for method, rawOp := range item {
			if !httpMethods[method] {
				continue
			}
			var op struct {
				Tags []string `json:"tags"`
			}
			if err := json.Unmarshal(rawOp, &op); err != nil {
				return nil, fmt.Errorf("conformance: parse %s %s: %w", method, path, err)
			}
			if len(op.Tags) == 0 {
				byTag[untaggedTag]++
				continue
			}
			for _, tag := range op.Tags {
				byTag[tag]++
			}
		}
	}
	return byTag, nil
}

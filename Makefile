.PHONY: test build lint conformance record

test:
	CGO_ENABLED=0 go test ./...

build:
	CGO_ENABLED=0 go build -o gloak ./cmd/gloak

lint:
	go vet ./...

conformance:
	CGO_ENABLED=0 go test ./internal/conformance/ -run TestCoverage -v

# record rewrites the expected values in internal/conformance/testdata/golden
# from a live Keycloak 26.7.1. It needs Docker. Read the diff before committing:
# an unreviewed re-record pins a regression as the new contract.
record:
	CGO_ENABLED=0 go test -tags docker ./internal/conformance/ -run TestRecordGoldens -v -count=1

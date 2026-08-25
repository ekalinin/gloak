.PHONY: test build lint conformance record oracle kcsrc

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

# oracle drives Gloak with kcadm.sh, the admin CLI that ships inside the
# Keycloak image, so a real client exercises fields no golden covers. It needs
# Docker, and a container that can reach the host, so it is not part of
# `make test`.
oracle:
	CGO_ENABLED=0 go test -tags docker ./internal/admin/ -run TestKcadm -v -count=1

# kcsrc materialises a read-only checkout of Keycloak's own test sources at the
# pinned tag, for mining behaviours the catalogue is missing. Nothing builds
# from it and nothing is copied out of it: see
# docs/superpowers/specs/2026-08-25-keycloak-upstream-testsuite-as-oracle.md.
KC_TESTSUITE_TAG := 26.7.1
KC_TESTSUITE_SHA := 73f08b397f193712b26d317210dce99898129709

kcsrc:
	@if [ ! -d .kc-testsuite ]; then \
		git clone --filter=blob:none --sparse --depth 1 \
			--branch $(KC_TESTSUITE_TAG) \
			https://github.com/keycloak/keycloak.git .kc-testsuite; \
		git -C .kc-testsuite sparse-checkout set tests test-framework; \
	fi
	@test "$$(git -C .kc-testsuite rev-parse HEAD)" = "$(KC_TESTSUITE_SHA)" \
		|| { echo "kcsrc: checkout is not $(KC_TESTSUITE_SHA)"; exit 1; }
	@echo "kcsrc: $(KC_TESTSUITE_TAG) at $(KC_TESTSUITE_SHA)"

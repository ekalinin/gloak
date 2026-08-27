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

# kcsrc materialises a sparse checkout of Keycloak's own test sources at the
# pinned tag, for mining behaviours the catalogue is missing. The discipline is
# that it is read-only: nothing builds from it, nothing is copied out of it,
# and it stays out of git. Nothing enforces that - see
# docs/superpowers/specs/2026-08-25-keycloak-upstream-testsuite-as-oracle.md.
#
# Sparse cone mode materialises the repository's root files as well as the two
# directories named here, so the working tree is $(KC_TESTSUITE_PATHS) plus the
# root of the tree, not only the two.
KC_TESTSUITE_TAG := 26.7.1
KC_TESTSUITE_SHA := 73f08b397f193712b26d317210dce99898129709
KC_TESTSUITE_PATHS := tests test-framework

# This target converges: every run drives the checkout to the pin rather than
# assuming a directory that exists is a directory that is right.
#
# It used to guard on `[ ! -d .kc-testsuite ]`, which had two failure modes. An
# interrupted clone left a directory every later run skipped, so the pin check
# below failed forever and its message did not say what to do about it. And
# changing KC_TESTSUITE_SHA or KC_TESTSUITE_PATHS did nothing at all to a
# checkout that already existed.
#
# So: the clone is guarded on .git rather than the directory, a failed clone
# removes what it left behind, the sparse paths are re-applied every run, and a
# checkout at the wrong commit is fetched and moved to the pin. Every failure
# that survives all that names the recovery.
kcsrc:
	@if [ ! -e .kc-testsuite/.git ]; then \
		rm -rf .kc-testsuite; \
		git clone --filter=blob:none --sparse --depth 1 \
			--branch $(KC_TESTSUITE_TAG) \
			https://github.com/keycloak/keycloak.git .kc-testsuite \
			|| { rm -rf .kc-testsuite; \
			     echo "kcsrc: clone failed; the partial checkout was removed, so just run 'make kcsrc' again"; \
			     exit 1; }; \
	fi
	@git -C .kc-testsuite sparse-checkout set $(KC_TESTSUITE_PATHS) \
		|| { echo "kcsrc: cannot apply the sparse paths; run 'rm -rf .kc-testsuite' and try again"; exit 1; }
	@if [ "$$(git -C .kc-testsuite rev-parse HEAD)" != "$(KC_TESTSUITE_SHA)" ]; then \
		git -C .kc-testsuite fetch --depth 1 origin $(KC_TESTSUITE_SHA) \
			&& git -C .kc-testsuite checkout --detach --force $(KC_TESTSUITE_SHA) \
			|| { echo "kcsrc: cannot move the checkout to $(KC_TESTSUITE_SHA); run 'rm -rf .kc-testsuite' and try again"; \
			     exit 1; }; \
	fi
	@test "$$(git -C .kc-testsuite rev-parse HEAD)" = "$(KC_TESTSUITE_SHA)" \
		|| { echo "kcsrc: checkout is not $(KC_TESTSUITE_SHA); run 'rm -rf .kc-testsuite' and try again"; exit 1; }
	@echo "kcsrc: $(KC_TESTSUITE_TAG) at $(KC_TESTSUITE_SHA)"

.PHONY: test build lint

test:
	CGO_ENABLED=0 go test ./...

build:
	CGO_ENABLED=0 go build -o gloak ./cmd/gloak

lint:
	go vet ./...

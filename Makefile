.PHONY: generate build test e2e e2e-tls

generate:
	go generate ./...

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/pgtrace-agent ./cmd/pgtrace-agent

test:
	go test -race ./...

e2e:
	./scripts/e2e.sh

e2e-tls:
	./scripts/e2e_tls.sh

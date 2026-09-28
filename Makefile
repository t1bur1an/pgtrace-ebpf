.PHONY: generate build test e2e

generate:
	go generate ./...

build:
	go build -o bin/pgtrace-agent ./cmd/pgtrace-agent

test:
	go test -race ./...

e2e:
	./scripts/e2e.sh

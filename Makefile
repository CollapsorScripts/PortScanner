.DEFAULT_GOAL := build

.PHONY: build run test vet fmt check

build:
	go build -o bin/portscanner ./cmd/portscanner

run:
	go run ./cmd/portscanner $(ARGS)

test:
	go test -race -timeout 60s ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal pkg

check: test vet

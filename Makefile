.PHONY: build test race vet fmt check clean

build:
	CGO_ENABLED=0 go build -trimpath -o bin/cinderlock ./cmd/cinderlock

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

check: test vet
	@test -z "$$(gofmt -l cmd internal)"

clean:
	go clean

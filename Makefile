# Reprodukovatelné sestavení (CRA): bez CGO, bez cest a build ID, verze z gitu.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)
GOFLAGS := -trimpath
export CGO_ENABLED := 0

.PHONY: build test vet dist clean

build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/contix-agent ./cmd/contix-agent

test:
	go test ./...

vet:
	go vet ./...

dist:
	GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/contix-agent-linux-amd64 ./cmd/contix-agent
	GOOS=linux   GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/contix-agent-linux-arm64 ./cmd/contix-agent
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/contix-agent-windows-amd64.exe ./cmd/contix-agent

clean:
	rm -rf bin dist

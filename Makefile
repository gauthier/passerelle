GO ?= go
BINDIR ?= bin
VERSION ?= 0.1.1
LDFLAGS := -s -w -X github.com/gauthier/passerelle/internal/version.Version=$(VERSION)

.PHONY: all build proto test clean deploy-gateway

all: build

proto:
	protoc --go_out=protocol/controlv1 --go_opt=paths=source_relative --proto_path=protocol protocol/control.proto

build:
	mkdir -p $(BINDIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINDIR)/passerelle ./cmd/passerelle
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINDIR)/passerelle-gateway ./cmd/passerelle-gateway

test:
	$(GO) test ./...

clean:
	rm -rf $(BINDIR)

deploy-gateway:
	./packaging/deploy-gateway.sh

BINARY  := snitch
PKG     := ./cmd/snitch
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build install test race vet fmt fmtcheck lint clean

build: ## Build the snitch binary
	go build $(LDFLAGS) -o $(BINARY) $(PKG)

install: ## Install snitch into $GOPATH/bin
	go install $(LDFLAGS) $(PKG)

test: ## Run the test suite
	go test ./...

race: ## Run tests with the race detector (needs a C compiler)
	go test -race ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Format the code
	gofmt -w .

fmtcheck: ## Fail if any file is not gofmt-clean
	@test -z "$$(gofmt -l .)" || (echo "unformatted files:"; gofmt -l .; exit 1)

lint: fmtcheck vet ## Format check + vet

clean: ## Remove build artifacts
	rm -f $(BINARY) $(BINARY).exe

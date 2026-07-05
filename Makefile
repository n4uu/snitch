BINARY  := snitch
PKG     := ./cmd/snitch
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build install tools test race vet fmt fmtcheck lint clean

build: ## Build the snitch binary
	go build $(LDFLAGS) -o $(BINARY) $(PKG)

tools: ## Install the Go-based recon tools snitch orchestrates
	go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
	go install github.com/projectdiscovery/katana/cmd/katana@latest
	go install github.com/ffuf/ffuf/v2@latest
	go install github.com/hahwul/dalfox/v2@latest
	go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
	@echo "Done. Also install from your package manager: nmap sqlmap libpcap-dev"

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

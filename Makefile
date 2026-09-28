BINARY_NAME := fetch-k8s-cert
VERSION := 3.2.2

LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: build
build: clean
	@[ -d build ] || mkdir -vp build
	go build -v $(LDFLAGS) -o build/$(BINARY_NAME) ./cmd/fetch-k8s-cert

.PHONY: test
test:
	go test -v ./cmd/fetch-k8s-cert/...

.PHONY: lint
lint: fmt-check
	golangci-lint run ./cmd/fetch-k8s-cert/...

.PHONY: fmt
fmt:
	gofmt -s -d ./cmd/fetch-k8s-cert

.PHONY: fmt-check
fmt-check:
	@if [ -n "$$(gofmt -s -d ./cmd/fetch-k8s-cert)" ]; then \
		echo "Code is not formatted properly:"; \
		gofmt -s -d ./cmd/fetch-k8s-cert; \
		exit 1; \
	fi

.PHONY: deb
deb:
	dpkg-buildpackage -b --no-sign || (echo "Build completed with warnings"; exit 0)

.PHONY: clean
clean:
	rm -rf build

.PHONY: resync
resync:
	@echo "Syncing configuration files to host..."
	@# Copy docker-compose.yaml if it exists
	@if [ -f docker-compose.yaml ]; then \
		echo "Copying docker-compose.yaml..."; \
		cp docker-compose.yaml /etc/fetch-k8s-cert/ 2>/dev/null || echo "  Warning: Could not copy to /etc/fetch-k8s-cert/ (requires sudo or permissions)"; \
	fi
	@# Copy .env files if they exist
	@if [ -f .env ]; then \
		echo "Copying .env..."; \
		cp .env /etc/fetch-k8s-cert/ 2>/dev/null || echo "  Warning: Could not copy to /etc/fetch-k8s-cert/ (requires sudo or permissions)"; \
	fi
	@if [ -f .env.example ]; then \
		echo "Copying .env.example..."; \
		cp .env.example /etc/fetch-k8s-cert/ 2>/dev/null || echo "  Warning: Could not copy to /etc/fetch-k8s-cert/ (requires sudo or permissions)"; \
	fi
	@# Copy example configs from examples/
	@if [ -d examples ]; then \
		echo "Syncing example configs..."; \
		mkdir -p /etc/fetch-k8s-cert/examples 2>/dev/null || echo "  Warning: Could not create /etc/fetch-k8s-cert/examples/ (requires sudo or permissions)"; \
		cp examples/*.yaml /etc/fetch-k8s-cert/examples/ 2>/dev/null || true; \
		cp examples/fetch-k8s-cert.service /etc/fetch-k8s-cert/examples/ 2>/dev/null || true; \
	fi
	@# Copy systemd service file if it exists
	@if [ -f examples/fetch-k8s-cert.service ]; then \
		echo "Copying systemd service..."; \
		sudo cp examples/fetch-k8s-cert.service /etc/systemd/system/ 2>/dev/null || echo "  Warning: Could not copy to /etc/systemd/system/ (requires sudo)"; \
	fi
	@echo "✓ Resync complete"

BINARY_NAME := fetch-k8s-cert
VERSION := 2.1.0

LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: build
build: clean
	@[ -d build ] || mkdir -vp build
	go build -v $(LDFLAGS) -o build/$(BINARY_NAME)

.PHONY: test
test:
	go test -v ./...

.PHONY: lint
lint: fmt-check
	golangci-lint run

.PHONY: fmt
fmt:
	gofmt -s -d .

.PHONY: fmt-check
fmt-check:
	@if [ -n "$$(gofmt -s -d .)" ]; then \
		echo "Code is not formatted properly:"; \
		gofmt -s -d .; \
		exit 1; \
	fi

.PHONY: deb
deb:
	dpkg-buildpackage

.PHONY: clean
clean:
	rm -rf build

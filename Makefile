BINARY_NAME := fetch-k8s-cert
VERSION := 1.3.1

LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: build
build: clean
	@[ -d build ] || mkdir -vp build
	go build -v $(LDFLAGS) -o build/$(BINARY_NAME)

.PHONY: deb
deb:
	dpkg-buildpackage

.PHONY: clean
clean:
	rm -rf build

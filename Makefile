BINARY_NAME := fetch-k8s-cert
VERSION := 1.3.1

LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: build
build: clean build-linux-amd64 # (for now)

build-linux-amd64:
	@[ -d build/linux/amd64 ] || mkdir -vp build/linux/amd64
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o build/linux/amd64/$(BINARY_NAME)

build-linux-arm64:
	@[ -d build/linux/arm64 ] || mkdir -vp build/linux/arm64
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o build/linux/arm64/$(BINARY_NAME)

# build-macos-arm64:
# 	@[ -d build/macos/arm64 ] || mkdir -vp build/macos/arm64
# 	GOOS=macosx GOARCH=arm64 go build $(LDFLAGS) -o build/macosx/arm64/$(BINARY_NAME)

build-windows-amd64:
	@[ -d build/windows/amd64 ] || mkdir -vp build/windows/amd64
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o build/windows/amd64/$(BINARY_NAME).exe

.PHONY: deb
deb:
	dpkg-buildpackage

.PHONY: clean
clean:
	rm -rf build



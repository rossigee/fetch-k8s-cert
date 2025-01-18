BINARY_NAME := fetch-k8s-cert
VERSION := 1.0.0

LDFLAGS=-ldflags "-X main.version=$(VERSION)"

build: clean
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)_linux_amd64
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_NAME)_linux_arm64
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)_windows_amd64.exe

package:
	dpkg-buildpackage

clean:
	rm -f $(BINARY_NAME)_*

.PHONY: build clean


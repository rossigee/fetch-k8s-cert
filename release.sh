#!/bin/bash

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 2.1.7"
    exit 1
fi

VERSION=$1

echo "Updating version to $VERSION..."

# Update main.go
sed -i "s/version = \".*\"/version = \"$VERSION\"/" main.go

# Update Makefile
sed -i "s/VERSION := .*/VERSION := $VERSION/" Makefile

# Update README.md title
sed -i "s/# Fetch K8s Certificate v.*/# Fetch K8s Certificate v$VERSION/" README.md

# Update README.md deb install example
sed -i "s/fetch-k8s-cert_.*_amd64.deb/fetch-k8s-cert_${VERSION}_amd64.deb/" README.md

# Update config-example.yaml
sed -i "s/fetch-k8s-cert v.*/fetch-k8s-cert v$VERSION/" config-example.yaml

# Update rpm spec
sed -i "s/Version: .*/Version: $VERSION/" rpmbuild/SPECS/fetch-k8s-cert.spec

# Update CHANGELOG.md - add new section
# Get previous version from CHANGELOG
PREV_VERSION=$(grep "^## \[" CHANGELOG.md | head -2 | tail -1 | sed 's/## \[//' | sed 's/\].*//')
DATE=$(date +%Y-%m-%d)

# Insert new section after the header
sed -i "/^## \[$PREV_VERSION\]/i ## [$VERSION] - $DATE\n\n### 🔧 Improvements\n\n- Release $VERSION\n\n---\n\n" CHANGELOG.md

echo "Version updated to $VERSION. Please review changes and add changelog details."
echo "Then run: git add . && git commit -m \"Release v$VERSION\" && git tag v$VERSION && git push origin master && git push origin v$VERSION"
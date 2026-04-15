#!/bin/bash
set -euo pipefail

# Builds all release artifacts, updates Package.swift, commits, tags, pushes,
# and creates a GitHub release — in the right order to avoid the chicken-and-egg
# problem with the xcframework checksum.
#
# Usage: ./scripts/build-release-artifacts.sh vX.Y.Z [--prerelease]
#
# Prerequisites:
#   - Rust toolchain with iOS targets (rustup target add aarch64-apple-ios aarch64-apple-ios-sim)
#   - gh CLI authenticated
#   - swift (for checksum computation)
#   - Clean working tree (no uncommitted changes)

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <version-tag> [--prerelease]"
    echo "Example: $0 v0.8.0 --prerelease"
    exit 1
fi

VERSION="$1"
PRERELEASE_FLAG="${2:-}"
CLIENT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="/tmp/wispers-release-$$"
REPO="s-te-ch/wispers-client"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION"

mkdir -p "$OUT"

echo "==> Building release artifacts for $VERSION"
echo "    Output: $OUT"

# --- Check for clean working tree ---
if [[ -n "$(git -C "$CLIENT_DIR" status --porcelain)" ]]; then
    echo "ERROR: Working tree is not clean. Commit or stash changes first."
    exit 1
fi

# --- Swift xcframework ---
echo ""
echo "==> Building Swift xcframework..."
cd "$CLIENT_DIR/wrappers/swift"
scripts/build-xcframework.sh --release
zip -r "$OUT/CWispersConnect.xcframework.zip" CWispersConnect.xcframework
CHECKSUM=$(swift package compute-checksum "$OUT/CWispersConnect.xcframework.zip")
echo "    Checksum: $CHECKSUM"

# Header (for the release — Go static libs are built by CI)
cd "$CLIENT_DIR"
cp wispers-connect/include/wispers_connect.h "$OUT/wispers_connect.h"

# --- Summary ---
echo ""
echo "==> Artifacts:"
ls -lh "$OUT/"

# --- Update Package.swift with checksum (URL is predictable) ---
echo ""
echo "==> Updating Package.swift..."
cd "$CLIENT_DIR"
# Update the root Package.swift (used by SPM consumers)
sed -i '' \
    -e "s|url: \"https://github.com/$REPO/releases/download/[^\"]*\"|url: \"$DOWNLOAD_URL/CWispersConnect.xcframework.zip\"|" \
    -e "s|checksum: \"[a-f0-9]*\"|checksum: \"$CHECKSUM\"|" \
    Package.swift
echo "    Updated Package.swift"

# --- Commit, tag, push ---
echo ""
read -p "Commit, tag $VERSION, and push? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted. Artifacts are in $OUT"
    echo "Package.swift has been modified but not committed."
    exit 0
fi

git -C "$CLIENT_DIR" add Package.swift
git -C "$CLIENT_DIR" commit -m "Update Package.swift for $VERSION"
git -C "$CLIENT_DIR" tag -a "$VERSION" -m "Release $VERSION"
git -C "$CLIENT_DIR" tag -a "wrappers/go/$VERSION" -m "Go module release $VERSION"
git -C "$CLIENT_DIR" push origin main "$VERSION" "wrappers/go/$VERSION"
echo "    Pushed main + tags"

# --- Create GitHub release (tag already exists) ---
echo ""
echo "==> Creating GitHub release..."
ASSETS=("$OUT"/*)
gh release create "$VERSION" \
    --repo "$REPO" \
    --verify-tag \
    ${PRERELEASE_FLAG:+"$PRERELEASE_FLAG"} \
    --title "$VERSION" \
    --notes "Release $VERSION" \
    "${ASSETS[@]}"
echo "==> Release created: https://github.com/$REPO/releases/tag/$VERSION"

echo ""
echo "==> Done. Remaining steps:"
echo "    1. Build Go static libs:  Trigger build-go-libs.yml workflow with version $VERSION"
echo "    2. Publish to crates.io:  cargo publish -p wispers-connect && cargo publish -p wcadm && cargo publish -p wconnect"
echo "    3. Publish to PyPI:       Trigger publish-python.yml workflow"
echo "    4. Publish to Maven:      cd wrappers/kotlin && ./gradlew buildNativeLibs publishAllPublicationsToMavenCentralRepository"

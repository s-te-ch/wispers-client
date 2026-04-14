#!/bin/bash
set -euo pipefail

# Builds all release artifacts and creates a GitHub release.
#
# Usage: ./scripts/build-release-artifacts.sh vX.Y.Z [--prerelease]
#
# Prerequisites:
#   - Rust toolchain with iOS targets (rustup target add aarch64-apple-ios aarch64-apple-ios-sim)
#   - gh CLI authenticated
#   - swift (for checksum computation)

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <version-tag> [--prerelease]"
    echo "Example: $0 v0.8.0 --prerelease"
    exit 1
fi

VERSION="$1"
PRERELEASE_FLAG="${2:-}"
CLIENT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="/tmp/wispers-release-$$"
mkdir -p "$OUT"

echo "==> Building release artifacts for $VERSION"
echo "    Output: $OUT"

# --- Swift xcframework ---
echo ""
echo "==> Building Swift xcframework..."
cd "$CLIENT_DIR/wrappers/swift"
scripts/build-xcframework.sh --release
zip -r "$OUT/CWispersConnect.xcframework.zip" CWispersConnect.xcframework
CHECKSUM=$(swift package compute-checksum "$OUT/CWispersConnect.xcframework.zip")
echo "    Checksum: $CHECKSUM"
echo ""
echo "    Update Package.swift with:"
echo "      checksum: \"$CHECKSUM\""
echo "      url: \"https://github.com/s-te-ch/wispers-client/releases/download/$VERSION/CWispersConnect.xcframework.zip\""

# --- Go static libraries ---
echo ""
echo "==> Building Go static libraries..."
cd "$CLIENT_DIR"

# macOS arm64 (native)
echo "    macOS arm64..."
MACOSX_DEPLOYMENT_TARGET=11.0 cargo rustc -p wispers-connect --release --crate-type staticlib 2>&1 | tail -1
cp target/release/libwispers_connect.a "$OUT/libwispers_connect-darwin_arm64.a"

# macOS x86_64
if rustup target list --installed | grep -q x86_64-apple-darwin; then
    echo "    macOS x86_64..."
    MACOSX_DEPLOYMENT_TARGET=11.0 cargo rustc -p wispers-connect --release --crate-type staticlib --target x86_64-apple-darwin 2>&1 | tail -1
    cp target/x86_64-apple-darwin/release/libwispers_connect.a "$OUT/libwispers_connect-darwin_amd64.a"
else
    echo "    macOS x86_64: SKIPPED (run: rustup target add x86_64-apple-darwin)"
fi

# Linux targets (skip if cross-compilation not available)
for target_arch in "aarch64-unknown-linux-gnu:linux_arm64" "x86_64-unknown-linux-gnu:linux_amd64"; do
    RUST_TARGET="${target_arch%%:*}"
    GO_PLATFORM="${target_arch##*:}"
    if rustup target list --installed | grep -q "$RUST_TARGET"; then
        echo "    $GO_PLATFORM..."
        cargo rustc -p wispers-connect --release --crate-type staticlib --target "$RUST_TARGET" 2>&1 | tail -1
        cp "target/$RUST_TARGET/release/libwispers_connect.a" "$OUT/libwispers_connect-${GO_PLATFORM}.a"
    else
        echo "    $GO_PLATFORM: SKIPPED (run: rustup target add $RUST_TARGET)"
    fi
done

# Header
cp wispers-connect/include/wispers_connect.h "$OUT/wispers_connect.h"

# --- Summary ---
echo ""
echo "==> Artifacts:"
ls -lh "$OUT/"

# --- Create GitHub release ---
echo ""
read -p "Create GitHub release $VERSION? [y/N] " confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
    ASSETS=("$OUT"/*)
    gh release create "$VERSION" \
        --repo s-te-ch/wispers-client \
        ${PRERELEASE_FLAG:+"$PRERELEASE_FLAG"} \
        --title "$VERSION" \
        --notes "Release $VERSION" \
        "${ASSETS[@]}"
    echo "==> Release created: https://github.com/s-te-ch/wispers-client/releases/tag/$VERSION"
else
    echo "Skipped. Upload manually with:"
    echo "  gh release create $VERSION --repo s-te-ch/wispers-client ${PRERELEASE_FLAG} $OUT/*"
fi

echo ""
echo "==> Done. Don't forget to:"
echo "    1. Update Package.swift with the checksum above"
echo "    2. Publish to crates.io, PyPI, and Maven Central"
echo "    3. Tag and push"

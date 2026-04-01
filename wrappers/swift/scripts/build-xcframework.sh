#!/bin/bash
set -euo pipefail

# Build wispers-connect as a static library for iOS targets and package
# as an XCFramework for consumption by Swift Package Manager / Xcode.
#
# Prerequisites:
#   - Xcode with iOS SDK
#   - rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#
# Usage: ./build-xcframework.sh [--release]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WRAPPER_DIR="$(dirname "$SCRIPT_DIR")"
CLIENT_DIR="$(dirname "$(dirname "$WRAPPER_DIR")")"
HEADER_DIR="$CLIENT_DIR/wispers-connect/include"

PROFILE="debug"
CARGO_FLAG=""
if [[ "${1:-}" == "--release" ]]; then
    PROFILE="release"
    CARGO_FLAG="--release"
fi

# Verify iOS SDK is available.
if ! IOS_SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path 2>&1); then
    echo "ERROR: Could not find iOS SDK. Is Xcode installed?"
    echo "  xcrun output: $IOS_SDKROOT"
    echo "  Try: sudo xcode-select -s /Applications/Xcode.app"
    exit 1
fi
if ! SIM_SDKROOT=$(xcrun --sdk iphonesimulator --show-sdk-path 2>&1); then
    echo "ERROR: Could not find iOS Simulator SDK."
    echo "  xcrun output: $SIM_SDKROOT"
    exit 1
fi
echo "iOS SDK:       $IOS_SDKROOT"
echo "Simulator SDK: $SIM_SDKROOT"

BUILD_DIR="$WRAPPER_DIR/build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "==> Building for aarch64-apple-ios (device)..."
cargo rustc -p wispers-connect --target aarch64-apple-ios \
    --crate-type staticlib $CARGO_FLAG \
    --manifest-path "$CLIENT_DIR/Cargo.toml"

echo "==> Building for aarch64-apple-ios-sim (simulator)..."
cargo rustc -p wispers-connect --target aarch64-apple-ios-sim \
    --crate-type staticlib $CARGO_FLAG \
    --manifest-path "$CLIENT_DIR/Cargo.toml"

# Resolve target dir (CARGO_TARGET_DIR may be overridden).
TARGET_DIR="${CARGO_TARGET_DIR:-$CLIENT_DIR/target}"
IOS_LIB="$TARGET_DIR/aarch64-apple-ios/$PROFILE/libwispers_connect.a"
SIM_LIB="$TARGET_DIR/aarch64-apple-ios-sim/$PROFILE/libwispers_connect.a"

for f in "$IOS_LIB" "$SIM_LIB"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: Expected library not found: $f"
        exit 1
    fi
done

# Create per-platform directories with headers.
for PLATFORM in ios ios-simulator; do
    mkdir -p "$BUILD_DIR/$PLATFORM/Headers"
    cp "$HEADER_DIR/wispers_connect.h" "$BUILD_DIR/$PLATFORM/Headers/"
    cat > "$BUILD_DIR/$PLATFORM/Headers/module.modulemap" <<'EOF'
module CWispersConnect {
    header "wispers_connect.h"
    export *
}
EOF
done

cp "$IOS_LIB" "$BUILD_DIR/ios/libwispers_connect.a"
cp "$SIM_LIB" "$BUILD_DIR/ios-simulator/libwispers_connect.a"

echo "==> Creating XCFramework..."
rm -rf "$WRAPPER_DIR/CWispersConnect.xcframework"
xcodebuild -create-xcframework \
    -library "$BUILD_DIR/ios/libwispers_connect.a" \
    -headers "$BUILD_DIR/ios/Headers" \
    -library "$BUILD_DIR/ios-simulator/libwispers_connect.a" \
    -headers "$BUILD_DIR/ios-simulator/Headers" \
    -output "$WRAPPER_DIR/CWispersConnect.xcframework"

rm -rf "$BUILD_DIR"

echo "==> Done: $WRAPPER_DIR/CWispersConnect.xcframework"

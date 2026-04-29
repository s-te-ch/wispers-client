#!/bin/sh
#
# install.sh — installer for wcadm and wconnect on macOS / Linux.
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/s-te-ch/wispers-client/main/scripts/install.sh | sh
#
# Environment variables:
#   VERSION     — release tag to install (default: latest, e.g. v0.8.1)
#   INSTALL_DIR — install directory (default: $HOME/.local/bin)
#   BINS        — space-separated list of binaries (default: "wcadm wconnect")

set -o errexit
set -o nounset

REPO="s-te-ch/wispers-client"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BINS="${BINS:-wcadm wconnect}"
VERSION="${VERSION:-}"

detect_target() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        darwin)
            case "$ARCH" in
                arm64|aarch64) printf '%s' "aarch64-apple-darwin" ;;
                x86_64) printf '%s' "x86_64-apple-darwin" ;;
                *) echo "Unsupported macOS arch: $ARCH" >&2; exit 1 ;;
            esac
            ;;
        linux)
            case "$ARCH" in
                aarch64|arm64) printf '%s' "aarch64-unknown-linux-gnu" ;;
                x86_64) printf '%s' "x86_64-unknown-linux-gnu" ;;
                *) echo "Unsupported Linux arch: $ARCH" >&2; exit 1 ;;
            esac
            ;;
        *)
            echo "Unsupported OS: $OS (use install.ps1 for Windows)" >&2
            exit 1
            ;;
    esac
}

resolve_version() {
    if [ -n "$VERSION" ]; then
        printf '%s' "$VERSION"
        return
    fi
    # GitHub redirects /releases/latest -> /releases/tag/<tag>; the final path
    # segment after the redirect is the tag.
    LATEST_URL=$(curl -sSfLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO/releases/latest")
    printf '%s' "${LATEST_URL##*/}"
}

main() {
    TARGET=$(detect_target)
    VERSION=$(resolve_version)

    if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
        echo "Could not resolve a release version." >&2
        exit 1
    fi

    # Strip leading 'v' for the archive filename (matches the artifact
    # naming in build-cli-binaries.yml).
    VERSION_NO_V="${VERSION#v}"

    echo "Installing wispers-client CLI tools"
    echo "  target:      $TARGET"
    echo "  version:     $VERSION"
    echo "  install dir: $INSTALL_DIR"
    echo

    mkdir -p "$INSTALL_DIR"

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    for BIN in $BINS; do
        ARCHIVE="${BIN}-${VERSION_NO_V}-${TARGET}.tar.gz"
        URL="https://github.com/$REPO/releases/download/$VERSION/$ARCHIVE"
        echo "  downloading $ARCHIVE"
        curl -sSfL -o "$TMPDIR/$ARCHIVE" "$URL"
        tar -C "$TMPDIR" -xzf "$TMPDIR/$ARCHIVE"
        mv -f "$TMPDIR/$BIN" "$INSTALL_DIR/$BIN"
        chmod +x "$INSTALL_DIR/$BIN"
        echo "  installed   $INSTALL_DIR/$BIN"
    done

    echo
    case ":$PATH:" in
        *":$INSTALL_DIR:"*)
            echo "Done. Try: $(echo "$BINS" | awk '{print $1}') --help"
            ;;
        *)
            echo "Done — but $INSTALL_DIR is not on your PATH."
            echo "Add this to your shell profile (e.g. ~/.bashrc, ~/.zshrc):"
            echo
            echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
            ;;
    esac
}

main

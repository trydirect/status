#!/bin/sh
# Status Panel installer
# Usage: curl -sSfL https://raw.githubusercontent.com/trydirect/status/master/install.sh | sh
#
# Environment variables:
#   VERSION     - Pin a specific version (e.g. "v0.1.4"). Default: latest release.
#   INSTALL_DIR - Installation directory. Default: /usr/local/bin

set -eu

REPO="trydirect/status"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

main() {
    detect_platform
    resolve_version
    download_binary
    verify_checksum
    install_binary
    echo ""
    echo "status ${VERSION} installed to ${INSTALL_DIR}/status"
    echo "Run 'status --help' to get started."
}

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux) ;;
        *)
            echo "Error: unsupported OS: $OS (only Linux is supported)" >&2
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64) ARCH="x86_64" ;;
        *)
            echo "Error: unsupported architecture: $ARCH (only x86_64 is supported)" >&2
            exit 1
            ;;
    esac

    ASSET_NAME="status-linux-${ARCH}-musl"
}

resolve_version() {
    if [ -n "${VERSION:-}" ]; then
        # Ensure version starts with 'v'
        case "$VERSION" in
            v*) ;;
            *)  VERSION="v${VERSION}" ;;
        esac
        return
    fi

    echo "Fetching latest release..."
    VERSION=$(
        curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'
    )

    if [ -z "$VERSION" ]; then
        echo "Error: could not determine latest version" >&2
        exit 1
    fi

    echo "Latest version: ${VERSION}"
}

download_binary() {
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}.sha256"

    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    echo "Downloading ${ASSET_NAME} ${VERSION}..."
    curl -sSfL -o "${TMPDIR}/${ASSET_NAME}" "$DOWNLOAD_URL"

    echo "Downloading checksum..."
    curl -sSfL -o "${TMPDIR}/${ASSET_NAME}.sha256" "$CHECKSUM_URL" || {
        echo "Warning: checksum file not available, skipping verification" >&2
        SKIP_CHECKSUM=1
    }
}

verify_checksum() {
    if [ "${SKIP_CHECKSUM:-0}" = "1" ]; then
        return
    fi

    echo "Verifying SHA256 checksum..."
    cd "$TMPDIR"

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c "${ASSET_NAME}.sha256"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c "${ASSET_NAME}.sha256"
    else
        echo "Warning: no sha256sum or shasum found, skipping verification" >&2
    fi

    cd - >/dev/null
}

install_binary() {
    chmod +x "${TMPDIR}/${ASSET_NAME}"

    # Ensure INSTALL_DIR exists
    if [ ! -d "$INSTALL_DIR" ]; then
        if mkdir -p "$INSTALL_DIR" 2>/dev/null; then
            :
        else
            if command -v sudo >/dev/null 2>&1; then
                echo "Creating installation directory ${INSTALL_DIR} with sudo..."
                sudo mkdir -p "$INSTALL_DIR"
            else
                echo "Error: installation directory ${INSTALL_DIR} does not exist and could not be created without sudo." >&2
                echo "Please create it manually or set INSTALL_DIR to a writable directory you own." >&2
                exit 1
            fi
        fi
    fi

    # Use sudo if we can't write to INSTALL_DIR
    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMPDIR}/${ASSET_NAME}" "${INSTALL_DIR}/status"
    else
        if command -v sudo >/dev/null 2>&1; then
            echo "Elevated permissions required to install to ${INSTALL_DIR}"
            sudo mv "${TMPDIR}/${ASSET_NAME}" "${INSTALL_DIR}/status"
        else
            echo "Error: cannot write to ${INSTALL_DIR} and sudo is not available." >&2
            echo "Please install manually or choose a different INSTALL_DIR." >&2
            exit 1
        fi
    fi
}

main

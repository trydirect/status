#!/usr/bin/env bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Stacker CLI installer
#
# Usage:
#   curl -fsSL https://get.stacker.dev/install.sh | bash
#   curl -fsSL https://get.stacker.dev/install.sh | bash -s -- --channel beta
#
# Environment variables:
#   STACKER_INSTALL_DIR  — where to install (default: /usr/local/bin)
#   STACKER_CHANNEL      — release channel: stable, beta (default: stable)
#   STACKER_VERSION      — pin to a specific version (e.g. 0.2.2)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -euo pipefail

REPO="trydirect/stacker"
INSTALL_DIR="${STACKER_INSTALL_DIR:-/usr/local/bin}"
CHANNEL="${STACKER_CHANNEL:-stable}"
VERSION="${STACKER_VERSION:-latest}"
BINARY_NAME="stacker"

# ── Helpers ──────────────────────────────────────────

info()  { printf "\033[1;34m▸\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m✓\033[0m %s\n" "$*"; }
err()   { printf "\033[1;31m✗\033[0m %s\n" "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || err "Required command not found: $1"
}

# ── Detect platform ─────────────────────────────────

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        *)       err "Unsupported OS: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "x86_64" ;;
        arm64|aarch64) echo "aarch64" ;;
        *)             err "Unsupported architecture: $(uname -m)" ;;
    esac
}

# ── Resolve version ─────────────────────────────────

resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        need curl
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' \
            | sed -E 's/.*"v?([^"]+)".*/\1/')
        [ -n "$VERSION" ] || err "Could not determine latest version"
    fi
    echo "$VERSION"
}

# ── Download & install ───────────────────────────────

download_and_install() {
    local os arch version archive_name url tmpdir

    os=$(detect_os)
    arch=$(detect_arch)
    version=$(resolve_version)

    archive_name="stacker-v${version}-${arch}-${os}.tar.gz"
    url="https://github.com/${REPO}/releases/download/v${version}/${archive_name}"

    info "Downloading stacker v${version} for ${os}/${arch}..."
    info "  ${url}"

    need curl
    need tar

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    curl -fsSL "$url" -o "${tmpdir}/${archive_name}" \
        || err "Download failed. Check the version exists: v${version}"

    tar -xzf "${tmpdir}/${archive_name}" -C "$tmpdir" \
        || err "Extraction failed"

    # Find the binary in the extracted archive
    local bin_path
    bin_path=$(find "$tmpdir" -name "$BINARY_NAME" -type f | head -1)
    [ -n "$bin_path" ] || bin_path=$(find "$tmpdir" -name "stacker-cli" -type f | head -1)
    [ -n "$bin_path" ] || err "Binary not found in archive"

    chmod +x "$bin_path"

    # Install
    if [ -w "$INSTALL_DIR" ]; then
        mv "$bin_path" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        info "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "$bin_path" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    ok "Installed stacker v${version} to ${INSTALL_DIR}/${BINARY_NAME}"
}

# ── Verify install ───────────────────────────────────

verify() {
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        ok "Verification: $($BINARY_NAME --version)"
    else
        info "Note: ${INSTALL_DIR} may not be in your PATH"
        info "  Add it:  export PATH=\"${INSTALL_DIR}:\$PATH\""
    fi
}

# ── Parse args ───────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --channel)  CHANNEL="$2"; shift 2 ;;
        --version)  VERSION="$2"; shift 2 ;;
        --dir)      INSTALL_DIR="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: install.sh [--channel stable|beta] [--version X.Y.Z] [--dir /path]"
            exit 0
            ;;
        *) err "Unknown option: $1" ;;
    esac
done

# ── Main ─────────────────────────────────────────────

info "Stacker CLI installer"
info "  Channel: ${CHANNEL}"
info "  Install dir: ${INSTALL_DIR}"
echo ""

download_and_install
verify

echo ""
ok "Done! Run 'stacker --help' to get started."

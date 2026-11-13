#!/usr/bin/env bash
# Render packaging/homebrew/status-panel.rb.tmpl into a Homebrew formula.
#
# Usage:
#   SHA256_AARCH64_APPLE_DARWIN=... \
#   SHA256_X86_64_APPLE_DARWIN=... \
#   SHA256_AARCH64_UNKNOWN_LINUX_MUSL=... \
#   SHA256_X86_64_UNKNOWN_LINUX_MUSL=... \
#     scripts/render-homebrew-formula.sh <version> [output-file]
#
# SHA256_* values are the checksums of the release tarballs:
#   status-panel-<version>-<target>.tar.gz
set -euo pipefail

VERSION="${1:?usage: render-homebrew-formula.sh <version> [output-file]}"
OUT="${2:-/dev/stdout}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="${ROOT}/packaging/homebrew/status-panel.rb.tmpl"

# VERSION comes from a git tag and is substituted into sed programs and Ruby
# string literals below; reject anything that is not a plain version number.
if ! [[ "${VERSION}" =~ ^[0-9]+(\.[0-9]+)+([-+][0-9A-Za-z.]+)?$ ]]; then
  echo "error: invalid version: ${VERSION}" >&2
  exit 1
fi

for var in \
  SHA256_AARCH64_APPLE_DARWIN \
  SHA256_X86_64_APPLE_DARWIN \
  SHA256_AARCH64_UNKNOWN_LINUX_MUSL \
  SHA256_X86_64_UNKNOWN_LINUX_MUSL; do
  if [ -z "${!var:-}" ]; then
    echo "error: ${var} is not set" >&2
    exit 1
  fi
done

sed \
  -e "s|@VERSION@|${VERSION}|g" \
  -e "s|@SHA256_AARCH64_APPLE_DARWIN@|${SHA256_AARCH64_APPLE_DARWIN}|g" \
  -e "s|@SHA256_X86_64_APPLE_DARWIN@|${SHA256_X86_64_APPLE_DARWIN}|g" \
  -e "s|@SHA256_AARCH64_UNKNOWN_LINUX_MUSL@|${SHA256_AARCH64_UNKNOWN_LINUX_MUSL}|g" \
  -e "s|@SHA256_X86_64_UNKNOWN_LINUX_MUSL@|${SHA256_X86_64_UNKNOWN_LINUX_MUSL}|g" \
  "${TEMPLATE}" > "${OUT}"

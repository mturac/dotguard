#!/usr/bin/env bash
set -euo pipefail

# dotguard installer
# Usage: curl -sSL https://raw.githubusercontent.com/YOUR_USER/dotguard/main/scripts/install.sh | bash

REPO="YOUR_USER/dotguard"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "🔒 Installing dotguard..."
echo "   OS: $OS | Arch: $ARCH"

LATEST=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
  echo "❌ Failed to fetch latest version"
  echo "   Try: go install github.com/${REPO}@latest"
  exit 1
fi

echo "   Version: v${LATEST}"

URL="https://github.com/${REPO}/releases/download/v${LATEST}/dotguard_${LATEST}_${OS}_${ARCH}.tar.gz"

TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

curl -sSL "$URL" -o "${TMP}/dotguard.tar.gz"
tar -xzf "${TMP}/dotguard.tar.gz" -C "$TMP"

if [ -w "$INSTALL_DIR" ]; then
  mv "${TMP}/dotguard" "${INSTALL_DIR}/dotguard"
else
  sudo mv "${TMP}/dotguard" "${INSTALL_DIR}/dotguard"
fi

chmod +x "${INSTALL_DIR}/dotguard"

echo "✅ dotguard v${LATEST} installed to ${INSTALL_DIR}/dotguard"
echo ""
echo "   Quick start:"
echo "     cd your-project"
echo "     dotguard init"
echo "     dotguard hook install"
echo "     dotguard scan"

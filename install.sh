#!/bin/sh
# wardn installer — https://vibeguard.io
# Usage: curl -sSf https://install.vibeguard.io | sh
set -e

REPO="rohansx/wardn"
INSTALL_DIR="${WARDN_INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)  OS="linux" ;;
        Darwin) OS="darwin" ;;
        *)
            echo "error: unsupported OS: $OS" >&2
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            echo "error: unsupported architecture: $ARCH" >&2
            exit 1
            ;;
    esac

    echo "${OS}-${ARCH}"
}

# Get latest release tag from GitHub API
get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//'
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//'
    else
        echo "error: curl or wget required" >&2
        exit 1
    fi
}

# Download a file
download() {
    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$1" -O "$2"
    fi
}

main() {
    echo "installing wardn..."

    PLATFORM="$(detect_platform)"
    VERSION="$(get_latest_version)"

    if [ -z "$VERSION" ]; then
        echo "error: could not determine latest version" >&2
        echo "try: cargo install wardn" >&2
        exit 1
    fi

    ARTIFACT="wardn-${PLATFORM}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARTIFACT}.tar.gz"

    echo "  version:  ${VERSION}"
    echo "  platform: ${PLATFORM}"
    echo "  target:   ${INSTALL_DIR}/wardn"
    echo ""

    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    echo "downloading ${URL}..."
    download "$URL" "${TMPDIR}/${ARTIFACT}.tar.gz"

    tar xzf "${TMPDIR}/${ARTIFACT}.tar.gz" -C "$TMPDIR"

    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMPDIR}/wardn" "${INSTALL_DIR}/wardn"
    else
        echo "installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "${TMPDIR}/wardn" "${INSTALL_DIR}/wardn"
    fi

    chmod +x "${INSTALL_DIR}/wardn"

    echo ""
    echo "wardn ${VERSION} installed to ${INSTALL_DIR}/wardn"
    echo ""
    echo "get started:"
    echo "  wardn vault create"
    echo "  wardn vault set OPENAI_KEY"
    echo "  wardn serve"
}

main

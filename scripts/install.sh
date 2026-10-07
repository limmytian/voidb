#!/usr/bin/env bash
# ==============================================================================
# VoidB Official One-Line Installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/limmytian/voidb/main/scripts/install.sh | bash
#   or:
#   curl -fsSL https://voidb.dev/install.sh | bash
# ==============================================================================
set -euo pipefail

REPO="limmytian/voidb"
INSTALL_DIR="${INSTALL_DIR:-}"
VERSION="${VOIDB_VERSION:-latest}"

TMP_DIR=""
cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

BOLD=$(printf '\033[1m')
GREEN=$(printf '\033[0;32m')
BLUE=$(printf '\033[0;34m')
YELLOW=$(printf '\033[0;33m')
RED=$(printf '\033[0;31m')
NC=$(printf '\033[0m')

info() {
    printf "${BLUE}==>${NC} ${BOLD}%s${NC}\n" "$1"
}

success() {
    printf "${GREEN}==>${NC} ${BOLD}%s${NC}\n" "$1"
}

warn() {
    printf "${YELLOW}warning:${NC} %s\n" "$1" >&2
}

error() {
    printf "${RED}error:${NC} %s\n" "$1" >&2
    exit 1
}

# Detect OS
detect_os() {
    local os
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
        darwin) echo "darwin" ;;
        linux) echo "linux" ;;
        *) error "Unsupported operating system: $os. VoidB supports macOS and Linux." ;;
    esac
}

# Detect Architecture
detect_arch() {
    local arch
    arch="$(uname -m | tr '[:upper:]' '[:lower:]')"
    case "$arch" in
        x86_64|amd64) echo "x64" ;;
        arm64|aarch64) echo "arm64" ;;
        *) error "Unsupported machine architecture: $arch. VoidB supports x86_64 and arm64." ;;
    esac
}

# Resolve target install directory
resolve_install_dir() {
    if [[ -n "$INSTALL_DIR" ]]; then
        echo "$INSTALL_DIR"
        return
    fi

    if [[ -w "/usr/local/bin" ]]; then
        echo "/usr/local/bin"
    elif [[ -d "$HOME/.local/bin" ]] || mkdir -p "$HOME/.local/bin" 2>/dev/null; then
        echo "$HOME/.local/bin"
    elif [[ -w "/usr/local" ]] && mkdir -p "/usr/local/bin" 2>/dev/null; then
        echo "/usr/local/bin"
    else
        echo "$HOME/bin"
    fi
}

# Determine download tool
fetch_file() {
    local url="$1"
    local output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$output" "$url"
    else
        error "Neither curl nor wget is available. Please install curl or wget."
    fi
}

main() {
    info "Starting VoidB installer..."

    local os
    os="$(detect_os)"
    local arch
    arch="$(detect_arch)"
    local target_platform="${os}-${arch}"
    info "Detected platform: ${BOLD}${target_platform}${NC}"

    local dest_dir
    dest_dir="$(resolve_install_dir)"
    info "Target install directory: ${BOLD}${dest_dir}${NC}"
    mkdir -p "$dest_dir"

    # Resolve version
    local tag="$VERSION"
    if [[ "$tag" == "latest" ]]; then
        info "Fetching latest release version from GitHub..."
        local api_url="https://api.github.com/repos/${REPO}/releases/latest"
        local release_json
        if command -v curl >/dev/null 2>&1; then
            release_json="$(curl -fsSL "$api_url" || true)"
        else
            release_json="$(wget -qO- "$api_url" || true)"
        fi

        if [[ -n "$release_json" ]]; then
            tag="$(echo "$release_json" | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d '"' -f 4 || true)"
        fi

        if [[ -z "$tag" ]]; then
            tag="v0.3.0"
            warn "Could not query latest release tag from GitHub API. Falling back to default: $tag"
        fi
    fi

    # Strip prefix 'v' for archive naming if present
    local clean_version="${tag#v}"
    local archive_name="voidb-${clean_version}-${target_platform}.tar.gz"
    local download_url="https://github.com/${REPO}/releases/download/${tag}/${archive_name}"

    TMP_DIR="$(mktemp -d -t voidb-install-XXXXXX)"

    info "Downloading VoidB ${tag} from ${download_url}..."
    if ! fetch_file "$download_url" "$TMP_DIR/$archive_name"; then
        error "Failed to download $archive_name from $download_url. Please verify network access or release availability."
    fi

    # Attempt to download SHA256SUMS and verify
    local sums_url="https://github.com/${REPO}/releases/download/${tag}/SHA256SUMS"
    if fetch_file "$sums_url" "$TMP_DIR/SHA256SUMS" 2>/dev/null; then
        info "Verifying SHA256 checksum..."
        local expected_sha
        expected_sha="$(grep "$archive_name" "$TMP_DIR/SHA256SUMS" | awk '{print $1}' || true)"
        if [[ -n "$expected_sha" ]]; then
            local actual_sha
            if command -v shasum >/dev/null 2>&1; then
                actual_sha="$(shasum -a 256 "$TMP_DIR/$archive_name" | awk '{print $1}')"
            elif command -v sha256sum >/dev/null 2>&1; then
                actual_sha="$(sha256sum "$TMP_DIR/$archive_name" | awk '{print $1}')"
            else
                actual_sha=""
            fi

            if [[ -n "$actual_sha" ]]; then
                if [[ "$actual_sha" != "$expected_sha" ]]; then
                    error "Checksum verification failed! Expected: $expected_sha, got: $actual_sha"
                fi
                info "Checksum verified successfully (${actual_sha:0:16}...)"
            fi
        fi
    fi

    info "Extracting archive..."
    tar -xzf "$TMP_DIR/$archive_name" -C "$TMP_DIR"

    # Install binaries
    local binaries=("voidb" "voidb-cli")
    for bin in "${binaries[@]}"; do
        if [[ -f "$TMP_DIR/$bin" ]]; then
            info "Installing ${bin} to ${dest_dir}/${bin}..."
            cp -f "$TMP_DIR/$bin" "$dest_dir/$bin"
            chmod +x "$dest_dir/$bin"
        elif [[ -f "$TMP_DIR/target/release/$bin" ]]; then
            info "Installing ${bin} to ${dest_dir}/${bin}..."
            cp -f "$TMP_DIR/target/release/$bin" "$dest_dir/$bin"
            chmod +x "$dest_dir/$bin"
        fi
    done

    # Verify installation
    if [[ -x "$dest_dir/voidb" ]] && [[ -x "$dest_dir/voidb-cli" ]]; then
        success "VoidB successfully installed!"
        printf "\n"
        printf "  %s  %s\n" "${BOLD}voidb${NC}:" "Main Interactive Terminal Database Manager"
        printf "  %s  %s\n" "${BOLD}voidb-cli${NC}:" "CLI & Plugin Manager"
        printf "\n"

        # Check if dest_dir is in PATH
        if [[ ":$PATH:" != *":$dest_dir:"* ]]; then
            warn "${dest_dir} is not in your current PATH."
            printf "Add it to your profile by running:\n"
            printf "  export PATH=\"%s:\$PATH\"\n\n" "$dest_dir"
        fi

        info "Quick Start:"
        printf "  1. Run VoidB TUI:       ${BOLD}voidb${NC}\n"
        printf "  2. Explore Marketplace: 按 'p' 打开可视化插件市场，或运行:\n"
        printf "     ${BOLD}voidb-cli plugin search${NC}\n"
        printf "  3. Install official plugins (e.g. MySQL, S3, Docker):\n"
        printf "     ${BOLD}voidb-cli plugin install mysql${NC}\n"
        printf "     ${BOLD}voidb-cli plugin install s3${NC}\n"
        printf "\n"
    else
        error "Installation failed: could not locate voidb binaries in archive."
    fi
}

main "$@"

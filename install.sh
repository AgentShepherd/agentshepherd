#!/bin/bash
#
# Crust Installer
# https://getcrust.io
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install.sh | bash
#
# Or with options:
#   curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install.sh | bash -s -- --version v1.0.0
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
GITHUB_REPO="BakeLens/crust"
INSTALL_DIR="$HOME/.local/bin"
BINARY_NAME="crust"
DATA_DIR="$HOME/.crust"

# Parse arguments
VERSION="latest"
while [[ $# -gt 0 ]]; do
    case $1 in
        --version|-v)
            VERSION="$2"
            shift 2
            ;;
        --help|-h)
            echo "Crust Installer"
            echo ""
            echo "Usage: curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install.sh | bash"
            echo ""
            echo "Options:"
            echo "  --version, -v    Install specific version (default: latest)"
            echo "  --help, -h       Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Print banner
echo -e "${BOLD}"
echo "    _                    _   ____  _                _                   _ "
echo "   / \\   __ _  ___ _ __ | |_/ ___|| |__   ___ _ __ | |__   ___ _ __ __| |"
echo "  / _ \\ / _\` |/ _ \\ '_ \\| __\\___ \\| '_ \\ / _ \\ '_ \\| '_ \\ / _ \\ '__/ _\` |"
echo " / ___ \\ (_| |  __/ | | | |_ ___) | | | |  __/ |_) | | | |  __/ | | (_| |"
echo "/_/   \\_\\__, |\\___|_| |_|\\__|____/|_| |_|\\___| .__/|_| |_|\\___|_|  \\__,_|"
echo "        |___/                                |_|                         "
echo -e "${NC}"
echo -e "${BLUE}Secure gateway for AI agents${NC}"
echo ""

# Detect OS
detect_os() {
    local os
    os="$(uname -s)"
    case "$os" in
        Darwin) echo "darwin" ;;
        Linux) echo "linux" ;;
        *) echo "unsupported" ;;
    esac
}

# Detect architecture
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "amd64" ;;
        arm64|aarch64) echo "arm64" ;;
        *) echo "unsupported" ;;
    esac
}

# Check for required commands
check_requirements() {
    local missing=()

    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        missing+=("curl or wget")
    fi

    if ! command -v git &> /dev/null; then
        missing+=("git")
    fi

    if ! command -v go &> /dev/null; then
        missing+=("go")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Error: Missing required commands: ${missing[*]}${NC}"
        echo "Install the missing tools and try again."
        exit 1
    fi
}

# Download file
download() {
    local url="$1"
    local output="$2"

    if command -v curl &> /dev/null; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget &> /dev/null; then
        wget -q "$url" -O "$output"
    fi
}

# Get latest version from GitHub releases API (falls back to main)
get_latest_version() {
    local url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local version
    if command -v curl &> /dev/null; then
        version=$(curl -fsSL "$url" 2>/dev/null | grep '"tag_name"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget &> /dev/null; then
        version=$(wget -qO- "$url" 2>/dev/null | grep '"tag_name"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    fi
    echo "${version:-main}"
}

# Main installation
main() {
    echo -e "${YELLOW}Detecting system...${NC}"

    local os
    local arch
    os=$(detect_os)
    arch=$(detect_arch)

    if [ "$os" = "unsupported" ]; then
        echo -e "${RED}Error: Unsupported operating system: $(uname -s)${NC}"
        echo "Crust supports macOS and Linux only."
        exit 1
    fi

    if [ "$arch" = "unsupported" ]; then
        echo -e "${RED}Error: Unsupported architecture: $(uname -m)${NC}"
        echo "Crust supports amd64 and arm64 only."
        exit 1
    fi

    echo -e "  OS: ${GREEN}$os${NC}"
    echo -e "  Arch: ${GREEN}$arch${NC}"
    echo ""

    check_requirements

    # Get version
    if [ "$VERSION" = "latest" ]; then
        echo -e "${YELLOW}Fetching latest version...${NC}"
        VERSION=$(get_latest_version)
    fi
    echo -e "  Version: ${GREEN}$VERSION${NC}"
    echo ""

    # Create temp directory
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

    echo -e "${YELLOW}Cloning repository...${NC}"
    if ! git clone --depth 1 --branch "$VERSION" "https://github.com/${GITHUB_REPO}.git" "$tmp_dir/crust" 2>/dev/null; then
        # Fallback to main if version tag doesn't exist
        git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$tmp_dir/crust"
    fi

    echo -e "${YELLOW}Building Crust...${NC}"
    cd "$tmp_dir/crust"
    go build -ldflags "-X main.Version=${VERSION#v}" -o crust .

    # Install binary
    echo -e "${YELLOW}Installing to ${INSTALL_DIR}...${NC}"
    mkdir -p "$INSTALL_DIR"
    mv "$tmp_dir/crust/crust" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"

    # Create data directory
    echo -e "${YELLOW}Creating data directory...${NC}"
    mkdir -p "$DATA_DIR"
    mkdir -p "$DATA_DIR/rules.d"

    # Verify installation
    echo ""
    echo -e "${GREEN}${BOLD}Crust installed successfully!${NC}"
    echo ""
    echo -e "  Binary: ${BLUE}${INSTALL_DIR}/${BINARY_NAME}${NC}"
    echo -e "  Data:   ${BLUE}${DATA_DIR}/${NC}"
    echo ""

    if ! command -v crust &> /dev/null; then
        echo -e "${YELLOW}Add ~/.local/bin to your PATH:${NC}"
        echo ""
        echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
        echo "  source ~/.bashrc"
        echo ""
    fi

    echo -e "${BOLD}Quick Start:${NC}"
    echo ""
    echo "  crust start                    # Start with interactive setup"
    echo "  crust status                   # Check status"
    echo "  crust logs -f                  # Follow logs"
    echo "  crust stop                     # Stop crust"
    echo ""
}

main "$@"

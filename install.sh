#!/bin/bash
#
# AgentShepherd Installer
# https://agentshepherd.ai
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/AgentShepherd/agentshepherd/main/install.sh | bash
#
# Or with options:
#   curl -fsSL https://raw.githubusercontent.com/AgentShepherd/agentshepherd/main/install.sh | bash -s -- --version v1.0.0
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
GITHUB_REPO="AgentShepherd/agentshepherd"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="agentshepherd"
DATA_DIR="$HOME/.agentshepherd"

# Parse arguments
VERSION="latest"
while [[ $# -gt 0 ]]; do
    case $1 in
        --version|-v)
            VERSION="$2"
            shift 2
            ;;
        --help|-h)
            echo "AgentShepherd Installer"
            echo ""
            echo "Usage: curl -fsSL https://raw.githubusercontent.com/AgentShepherd/agentshepherd/main/install.sh | bash"
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

    if ! command -v tar &> /dev/null; then
        missing+=("tar")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Error: Missing required commands: ${missing[*]}${NC}"
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

# Get latest version from GitHub
get_latest_version() {
    local url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    if command -v curl &> /dev/null; then
        curl -fsSL "$url" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
    elif command -v wget &> /dev/null; then
        wget -qO- "$url" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
    fi
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
        echo "AgentShepherd supports macOS and Linux only."
        exit 1
    fi

    if [ "$arch" = "unsupported" ]; then
        echo -e "${RED}Error: Unsupported architecture: $(uname -m)${NC}"
        echo "AgentShepherd supports amd64 and arm64 only."
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
        if [ -z "$VERSION" ]; then
            echo -e "${RED}Error: Could not determine latest version${NC}"
            echo "Please specify a version with --version"
            exit 1
        fi
    fi
    echo -e "  Version: ${GREEN}$VERSION${NC}"
    echo ""

    # Build download URL
    local filename="agentshepherd-${VERSION}-${os}-${arch}.tar.gz"
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${filename}"

    # Create temp directory
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

    echo -e "${YELLOW}Downloading AgentShepherd...${NC}"
    echo "  $download_url"

    if ! download "$download_url" "$tmp_dir/$filename" 2>/dev/null; then
        echo -e "${RED}Error: Failed to download AgentShepherd${NC}"
        echo ""
        echo "The release may not exist yet. You can build from source:"
        echo ""
        echo "  git clone https://github.com/${GITHUB_REPO}"
        echo "  cd agentshepherd"
        echo "  go build -o agentshepherd ."
        echo "  sudo mv agentshepherd /usr/local/bin/"
        exit 1
    fi

    echo -e "${YELLOW}Extracting...${NC}"
    tar -xzf "$tmp_dir/$filename" -C "$tmp_dir"

    # Install binary
    echo -e "${YELLOW}Installing to ${INSTALL_DIR}...${NC}"

    if [ -w "$INSTALL_DIR" ]; then
        mv "$tmp_dir/agentshepherd" "$INSTALL_DIR/$BINARY_NAME"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
    else
        echo -e "${YELLOW}Requesting sudo access to install to ${INSTALL_DIR}${NC}"
        sudo mv "$tmp_dir/agentshepherd" "$INSTALL_DIR/$BINARY_NAME"
        sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
    fi

    # Create data directory
    echo -e "${YELLOW}Creating data directory...${NC}"
    mkdir -p "$DATA_DIR"
    mkdir -p "$DATA_DIR/rules.d"

    # Verify installation
    if command -v agentshepherd &> /dev/null; then
        echo ""
        echo -e "${GREEN}${BOLD}AgentShepherd installed successfully!${NC}"
        echo ""
        echo -e "  Binary: ${BLUE}${INSTALL_DIR}/${BINARY_NAME}${NC}"
        echo -e "  Data:   ${BLUE}${DATA_DIR}/${NC}"
        echo ""
        echo -e "${BOLD}Quick Start:${NC}"
        echo ""
        echo "  agentshepherd start                    # Start with interactive setup"
        echo "  agentshepherd status                   # Check status"
        echo "  agentshepherd logs -f                  # Follow logs"
        echo "  agentshepherd stop                     # Stop agentshepherd"
        echo ""
        echo -e "${BOLD}Documentation:${NC} https://agentshepherd.ai/docs"
        echo ""
    else
        echo -e "${YELLOW}Warning: agentshepherd was installed but is not in your PATH${NC}"
        echo ""
        echo "Add ${INSTALL_DIR} to your PATH:"
        echo ""
        echo "  export PATH=\"\$PATH:${INSTALL_DIR}\""
        echo ""
    fi
}

main "$@"

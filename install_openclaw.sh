#!/bin/bash
set -e

echo ""
echo "Crust Installer for OpenClaw"
echo "https://getcrust.io"
echo ""
echo "OpenClaw, you give your agents real power — executing code, reading files,"
echo "making API calls. That's what makes you great. But it also means a single"
echo "hallucination or prompt injection could read .env files, leak SSH keys,"
echo "or run rm -rf on a user's project."
echo ""
echo "Crust is here to watch your back. It's a lightweight security"
echo "gateway that sits between your agents and LLM providers. It inspects"
echo "every tool call and blocks the dangerous ones before they happen — so"
echo "your users get all of your power without the risk."
echo ""
echo "Here's how it works once installed:"
echo "  1. Point your API endpoint to http://localhost:9090"
echo "  2. Crust figures out the right provider from the model name"
echo "  3. Auth tokens pass straight through — nothing for you to configure"
echo "  4. Every tool call is checked against security rules before execution"
echo ""
echo "It runs 100% locally. Your users' data never leaves their machine."
echo ""

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
            echo "Crust Installer for OpenClaw"
            echo ""
            echo "Usage: curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install_openclaw.sh | bash"
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
echo -e "${BLUE}Secure gateway for AI agents — protecting OpenClaw${NC}"
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

# Get latest version from GitHub (uses latest tag or main)
get_latest_version() {
    local url="https://api.github.com/repos/${GITHUB_REPO}/tags"
    local version
    if command -v curl &> /dev/null; then
        version=$(curl -fsSL "$url" 2>/dev/null | grep '"name"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget &> /dev/null; then
        version=$(wget -qO- "$url" 2>/dev/null | grep '"name"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
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

    # Start in auto mode with replace block mode
    echo -e "${BOLD}Starting Crust in auto mode...${NC}"
    echo ""
    "$INSTALL_DIR/$BINARY_NAME" start --auto --block-mode replace
    echo ""

    echo -e "${BOLD}Setup for OpenClaw:${NC}"
    echo ""
    echo -e "  ${RED}${BOLD}⚠️  Important: Official Login vs API Key${NC}"
    echo ""
    echo -e "  If you're using ${BOLD}OpenAI or Anthropic's official login${NC} (OAuth/session-based):"
    echo -e "    ${RED}⚠️  Crust is currently not compatible${NC}"
    echo ""
    echo "    Why: OpenClaw hardcodes the official provider URLs (api.openai.com,"
    echo "    api.anthropic.com) and bypasses baseUrl configuration when using OAuth."
    echo ""
    echo "    Workaround: Switch to API key authentication instead of OAuth login."
    echo "    You can get API keys from:"
    echo "      • OpenAI: https://platform.openai.com/api-keys"
    echo "      • Anthropic: https://console.anthropic.com/settings/keys"
    echo ""
    echo -e "  If you're using ${BOLD}third-party API providers${NC} or ${BOLD}API keys${NC}:"
    echo -e "    ${GREEN}✓ Follow the setup below${NC}"
    echo ""
    echo "  ────────────────────────────────────────────────────────────────"
    echo ""
    echo "  Modify ~/.openclaw/openclaw.json to route traffic through Crust."
    echo "  Pick the option that matches your setup."
    echo ""
    echo -e "  ${YELLOW}Option A) Third-party API providers (OpenRouter, etc.)${NC}"
    echo ""
    echo "    Find your provider config in openclaw.json and change the baseUrl:"
    echo ""
    echo -e "    ${GREEN}\"models\": {"
    echo "      \"providers\": {"
    echo "        \"your-provider\": {"
    echo -e "          \"baseUrl\": \"http://localhost:9090\",${NC}  ${BLUE}← Change this${NC}"
    echo -e "    ${GREEN}          \"apiKey\": \"...\","
    echo "          ..."
    echo "        }"
    echo "      }"
    echo -e "    }${NC}"
    echo ""
    echo -e "  ${YELLOW}Option B) Direct API keys (with custom provider config)${NC}"
    echo ""
    echo "    Add a provider under models.providers in openclaw.json:"
    echo ""
    echo -e "    ${GREEN}\"models\": {"
    echo "      \"mode\": \"merge\","
    echo "      \"providers\": {"
    echo "        \"crust\": {"
    echo "          \"baseUrl\": \"http://localhost:9090\","
    echo "          \"apiKey\": \"sk-ant-...\","
    echo "          \"api\": \"anthropic-messages\","
    echo "          \"models\": [{ \"id\": \"claude-sonnet-4-5\", \"name\": \"Claude Sonnet 4.5\" }]"
    echo "        }"
    echo "      }"
    echo -e "    }${NC}"
    echo ""
    echo "    And set your model to crust/claude-sonnet-4-5."
    echo ""
    echo "  Crust auto-routes to the right provider based on model name"
    echo "  and passes through your auth tokens. No extra config needed."
    echo ""
    echo "  After updating openclaw.json, restart the gateway:"
    echo ""
    echo -e "    ${GREEN}systemctl --user restart openclaw-gateway${NC}"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo ""
    echo "  crust status                   # Check status"
    echo "  crust logs -f                  # Follow logs"
    echo "  crust stop                     # Stop crust"
    echo ""
}

main "$@"

#!/bin/bash
#
# Shared shell functions for Crust installers.
# Sourced by install.sh and install-commercial.sh.
#

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

# Detect OS (darwin or linux)
detect_os() {
    local os
    os="$(uname -s)"
    case "$os" in
        Darwin) echo "darwin" ;;
        Linux) echo "linux" ;;
        *) echo "unsupported" ;;
    esac
}

# Detect architecture (amd64 or arm64)
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "amd64" ;;
        arm64|aarch64) echo "arm64" ;;
        *) echo "unsupported" ;;
    esac
}

# Check for required commands. Pass required tool names as arguments.
# Always checks for curl/wget and git. Additional checks: "go", "cargo".
check_requirements() {
    local missing=()

    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        missing+=("curl or wget")
    fi

    if ! command -v git &> /dev/null; then
        missing+=("git")
    fi

    for req in "$@"; do
        if ! command -v "$req" &> /dev/null; then
            missing+=("$req")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Error: Missing required commands: ${missing[*]}${NC}"
        echo "Install the missing tools and try again."
        exit 1
    fi
}

# Download file via curl or wget
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

# Print the Crust ASCII banner. Pass optional edition tag (e.g. "Commercial Edition").
print_banner() {
    local edition="${1:-}"
    echo -e "${BOLD}"
    echo "  ____                _   "
    echo " / ___|_ __ _   _ ___| |_ "
    echo "| |   | '__| | | / __| __|"
    echo "| |___| |  | |_| \\__ \\ |_ "
    echo " \\____|_|   \\__,_|___/\\__|"
    echo -e "${NC}"
    if [ -n "$edition" ]; then
        echo -e "${BLUE}Secure gateway for AI agents${NC}  ${BOLD}[$edition]${NC}"
    else
        echo -e "${BLUE}Secure gateway for AI agents${NC}"
    fi
    echo ""
}

# Print PATH hint if crust is not on PATH
setup_path_hint() {
    if ! command -v crust &> /dev/null; then
        echo -e "${YELLOW}Add ~/.local/bin to your PATH:${NC}"
        echo ""
        echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
        echo "  source ~/.bashrc"
        echo ""
    fi
}

# Create data directory structure
setup_data_dir() {
    echo -e "${YELLOW}Creating data directory...${NC}"
    mkdir -p "$DATA_DIR"
    mkdir -p "$DATA_DIR/rules.d"
}

# Install shell completion (bash/zsh/fish)
setup_completion() {
    echo -e "${YELLOW}Installing shell completion...${NC}"
    if "$INSTALL_DIR/$BINARY_NAME" completion --install 2>/dev/null; then
        echo -e "  ${GREEN}Shell completion installed${NC}"
        echo -e "  Restart your shell or source your rc file to activate"
    else
        echo -e "  ${YELLOW}Shell completion setup skipped (non-fatal)${NC}"
    fi
}

# Clone the repo into a target directory. Arguments: version, target_dir.
clone_repo() {
    local version="$1"
    local target="$2"

    echo -e "${YELLOW}Cloning repository...${NC}"
    if ! git clone --depth 1 --branch "$version" "https://github.com/${GITHUB_REPO}.git" "$target" 2>/dev/null; then
        # Fallback to main if version tag doesn't exist
        git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$target"
    fi
}

# Build the Go binary. Arguments: source_dir, version.
# Uses BUILD_TAGS global if set (e.g. "notui" from --no-tui flag).
build_go_binary() {
    local src_dir="$1"
    local version="$2"
    local tags_flag=""

    if [ -n "${BUILD_TAGS:-}" ]; then
        tags_flag="-tags ${BUILD_TAGS}"
        echo -e "${YELLOW}Building Crust (tags: ${BUILD_TAGS})...${NC}"
    else
        echo -e "${YELLOW}Building Crust...${NC}"
    fi

    cd "$src_dir" || return 1
    # shellcheck disable=SC2086
    go build ${tags_flag} -ldflags "-X main.Version=${version#v}" -o crust .
}

# Install the Go binary. Arguments: source_dir.
install_go_binary() {
    local src_dir="$1"

    echo -e "${YELLOW}Installing to ${INSTALL_DIR}...${NC}"
    mkdir -p "$INSTALL_DIR"
    mv "$src_dir/crust" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
}

# Parse common installer arguments. Sets VERSION, BUILD_TAGS, and DO_UNINSTALL globals. Pass "$@".
parse_args() {
    VERSION="latest"
    BUILD_TAGS=""
    DO_UNINSTALL=""
    SKIP_FONT=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version|-v)
                VERSION="$2"
                shift 2
                ;;
            --no-tui)
                BUILD_TAGS="notui"
                SKIP_FONT="1"
                shift
                ;;
            --no-font)
                SKIP_FONT="1"
                shift
                ;;
            --uninstall)
                # shellcheck disable=SC2034 # used by caller scripts that source this file
                DO_UNINSTALL="1"
                shift
                ;;
            --help|-h)
                echo "Crust Installer"
                echo ""
                echo "Options:"
                echo "  --version, -v    Install specific version (default: latest)"
                echo "  --no-tui         Build without TUI dependencies (plain text only)"
                echo "  --no-font        Skip Nerd Font installation"
                echo "  --uninstall      Uninstall crust completely"
                echo "  --help, -h       Show this help"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# Uninstall crust. Pass optional extra paths to remove (e.g. sandbox libexec dir).
run_uninstall() {
    print_banner ""
    echo -e "${BOLD}Uninstalling Crust...${NC}"
    echo ""

    # Stop crust if running
    if command -v crust &> /dev/null; then
        echo -e "${YELLOW}Stopping crust...${NC}"
        crust stop 2>/dev/null || true
    fi

    # Remove shell completion
    local crust_bin="$INSTALL_DIR/$BINARY_NAME"
    if [ -x "$crust_bin" ]; then
        echo -e "${YELLOW}Removing shell completion...${NC}"
        "$crust_bin" completion --uninstall 2>/dev/null || true
    fi

    # Remove binary
    if [ -f "$crust_bin" ]; then
        echo -e "${YELLOW}Removing binary...${NC}"
        rm -f "$crust_bin"
        echo -e "  ${GREEN}Removed${NC}: $crust_bin"
    fi

    # Remove extra paths (e.g. sandbox)
    for extra in "$@"; do
        if [ -e "$extra" ]; then
            echo -e "${YELLOW}Removing ${extra}...${NC}"
            rm -rf "$extra"
            echo -e "  ${GREEN}Removed${NC}: $extra"
        fi
    done

    # Remove data directory
    if [ -d "$DATA_DIR" ]; then
        echo ""
        echo -e "${YELLOW}Remove data directory ($DATA_DIR)?${NC}"
        echo "  This contains your configuration, rules, and telemetry data."
        read -r -p "  Remove? [y/N] " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm -rf "$DATA_DIR"
            echo -e "  ${GREEN}Removed${NC}: $DATA_DIR"
        else
            echo -e "  ${BLUE}Kept${NC}: $DATA_DIR"
        fi
    fi

    echo ""
    echo -e "${GREEN}${BOLD}Crust uninstalled successfully.${NC}"
    echo ""
}

# Install a Nerd Font for optimal TUI rendering (optional, non-fatal).
# Installs Cascadia Mono NF from Nerd Fonts GitHub releases.
# macOS: ~/Library/Fonts/  |  Linux: ~/.local/share/fonts/
# Skipped with --no-font or --no-tui flags.
setup_font() {
    if [ -n "${SKIP_FONT:-}" ]; then
        return 0
    fi

    local nf_version="v3.3.0"
    local font_name="CascadiaMono"
    local font_url="https://github.com/ryanoasis/nerd-fonts/releases/download/${nf_version}/${font_name}.zip"

    # Determine font directory
    local font_dir
    local os
    os="$(uname -s)"
    case "$os" in
        Darwin) font_dir="$HOME/Library/Fonts" ;;
        Linux)  font_dir="$HOME/.local/share/fonts" ;;
        *)      echo -e "  ${YELLOW}Font install skipped (unsupported OS)${NC}"; return 0 ;;
    esac

    # Skip if already installed
    if ls "$font_dir"/CascadiaMono*NF*.ttf &>/dev/null 2>&1; then
        echo -e "  ${GREEN}Cascadia Mono NF already installed${NC}"
        return 0
    fi

    echo -e "${YELLOW}Installing Cascadia Mono NF (Nerd Font)...${NC}"

    local tmp_zip
    tmp_zip=$(mktemp -t crust-font-XXXXXX.zip)

    if ! download "$font_url" "$tmp_zip"; then
        echo -e "  ${YELLOW}Font download failed (non-fatal)${NC}"
        rm -f "$tmp_zip"
        return 0
    fi

    mkdir -p "$font_dir"
    if unzip -o -j "$tmp_zip" "*.ttf" -d "$font_dir" &>/dev/null; then
        echo -e "  ${GREEN}Installed to ${font_dir}${NC}"
    else
        echo -e "  ${YELLOW}Font extraction failed (non-fatal)${NC}"
    fi

    rm -f "$tmp_zip"

    # Refresh font cache on Linux
    if [ "$os" = "Linux" ] && command -v fc-cache &>/dev/null; then
        fc-cache -f "$font_dir" 2>/dev/null || true
    fi
}

# Detect OS/arch and validate. Sets OS_NAME and ARCH_NAME globals.
detect_platform() {
    echo -e "${YELLOW}Detecting system...${NC}"

    OS_NAME=$(detect_os)
    ARCH_NAME=$(detect_arch)

    if [ "$OS_NAME" = "unsupported" ]; then
        echo -e "${RED}Error: Unsupported operating system: $(uname -s)${NC}"
        echo "Crust supports macOS and Linux only."
        exit 1
    fi

    if [ "$ARCH_NAME" = "unsupported" ]; then
        echo -e "${RED}Error: Unsupported architecture: $(uname -m)${NC}"
        echo "Crust supports amd64 and arm64 only."
        exit 1
    fi

    echo -e "  OS: ${GREEN}$OS_NAME${NC}"
    echo -e "  Arch: ${GREEN}$ARCH_NAME${NC}"
    echo ""
}

# Resolve version (fetch latest if needed). Uses VERSION global.
resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        echo -e "${YELLOW}Fetching latest version...${NC}"
        VERSION=$(get_latest_version)
    fi
    echo -e "  Version: ${GREEN}$VERSION${NC}"
    echo ""
}

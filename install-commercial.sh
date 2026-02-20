#!/bin/bash
#
# Crust Installer (Commercial Edition)
# https://getcrust.io
#
# Installs Crust Go binary + Rust sandbox (includes LSM daemon).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install-commercial.sh | bash
#
# Or with options:
#   curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install-commercial.sh | bash -s -- --version v2.0.0
#

set -e

# Source shared functions (works for both local and piped execution)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/scripts/install-common.sh" ]; then
    # shellcheck source=scripts/install-common.sh
    source "$SCRIPT_DIR/scripts/install-common.sh"
else
    # When piped via curl, download common script to temp
    _common_tmp=$(mktemp)
    trap 'rm -f "$_common_tmp"' EXIT
    if command -v curl &> /dev/null; then
        curl -fsSL "https://raw.githubusercontent.com/BakeLens/crust/main/scripts/install-common.sh" -o "$_common_tmp"
    elif command -v wget &> /dev/null; then
        wget -q "https://raw.githubusercontent.com/BakeLens/crust/main/scripts/install-common.sh" -O "$_common_tmp"
    else
        echo "Error: curl or wget required" >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$_common_tmp"
fi

# Build the Rust sandbox binary. Arguments: source_dir.
build_rust_sandbox() {
    local src_dir="$1"
    local sandbox_dir="$src_dir/cmd/bakelens-sandbox"

    if [ ! -d "$sandbox_dir" ]; then
        echo -e "${YELLOW}Sandbox source not found, skipping...${NC}"
        return 1
    fi

    echo -e "${YELLOW}Building Rust sandbox...${NC}"
    cd "$sandbox_dir"
    cargo build --release 2>&1
    echo -e "  ${GREEN}Sandbox built${NC}"
}

# Install the Rust sandbox binary. Arguments: source_dir.
install_rust_sandbox() {
    local src_dir="$1"
    local binary="$src_dir/cmd/bakelens-sandbox/target/release/bakelens-sandbox"

    if [ ! -f "$binary" ]; then
        echo -e "${YELLOW}Sandbox binary not found, skipping install...${NC}"
        return 1
    fi

    echo -e "${YELLOW}Installing sandbox to ${LIBEXEC_DIR}...${NC}"
    mkdir -p "$LIBEXEC_DIR"
    cp "$binary" "$LIBEXEC_DIR/bakelens-sandbox"
    chmod +x "$LIBEXEC_DIR/bakelens-sandbox"
    echo -e "  ${GREEN}Installed${NC}: ${BLUE}${LIBEXEC_DIR}/bakelens-sandbox${NC}"
}

# Run sandbox consistency check (best-effort).
verify_sandbox() {
    if command -v crust &> /dev/null; then
        echo -e "${YELLOW}Verifying sandbox...${NC}"
        if crust check-sandbox 2>/dev/null; then
            echo -e "  ${GREEN}Sandbox OK${NC}"
        else
            echo -e "  ${YELLOW}Sandbox check returned warnings (non-fatal)${NC}"
        fi
    fi
}

LIBEXEC_DIR="$HOME/.local/libexec/crust"

main() {
    parse_args "$@"

    if [ -n "$DO_UNINSTALL" ]; then
        run_uninstall "$LIBEXEC_DIR"
        exit 0
    fi

    print_banner "Commercial Edition"
    detect_platform
    check_requirements "go" "cargo"
    resolve_version

    # Create temp directory
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

    # Clone and build Go binary
    clone_repo "$VERSION" "$tmp_dir/crust"
    build_go_binary "$tmp_dir/crust" "$VERSION"
    install_go_binary "$tmp_dir/crust"

    # Build and install Rust sandbox
    if build_rust_sandbox "$tmp_dir/crust"; then
        install_rust_sandbox "$tmp_dir/crust"
    fi

    setup_data_dir
    setup_completion
    setup_font

    # Verify
    verify_sandbox

    # Success
    echo ""
    echo -e "${GREEN}${BOLD}Crust (Commercial Edition) installed successfully!${NC}"
    echo ""
    echo -e "  Binary:  ${BLUE}${INSTALL_DIR}/${BINARY_NAME}${NC}"
    echo -e "  Sandbox: ${BLUE}${LIBEXEC_DIR}/bakelens-sandbox${NC}"
    echo -e "  Data:    ${BLUE}${DATA_DIR}/${NC}"
    echo ""

    setup_path_hint

    echo -e "${BOLD}Quick Start:${NC}"
    echo ""
    echo "  crust start                    # Start with interactive setup"
    echo "  crust wrap <command>           # Run command in sandbox"
    echo "  crust check-sandbox            # Verify sandbox setup"
    echo "  crust status                   # Check status"
    echo "  crust logs -f                  # Follow logs"
    echo "  crust stop                     # Stop crust"
    echo ""
}

main "$@"

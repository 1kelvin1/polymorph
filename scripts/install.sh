#!/bin/bash
# PolyMorph installation script

set -e

echo "═══════════════════════════════════════════════════════"
echo "  PolyMorph Installation"
echo "═══════════════════════════════════════════════════════"
echo ""

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

echo "✓ Rust found: $(rustc --version)"
echo ""

# Build
echo "[1/3] Building PolyMorph..."
cargo build --release

echo ""
echo "[2/3] Running tests..."
cargo test --release

echo ""
echo "[3/3] Installing binary..."

# Install to system
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

if [ -w "$INSTALL_DIR" ]; then
    cp target/release/polymorph "$INSTALL_DIR/"
    echo "✓ Installed to $INSTALL_DIR/polymorph"
else
    echo "⚠️  Cannot write to $INSTALL_DIR (run with sudo or specify INSTALL_DIR)"
    echo ""
    echo "Install manually:"
    echo "  sudo cp target/release/polymorph /usr/local/bin/"
    echo ""
    echo "Or use locally:"
    echo "  ./target/release/polymorph"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Installation Complete!"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Usage:"
echo "  polymorph --help"
echo "  polymorph suspicious.exe"
echo ""

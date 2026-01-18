#!/bin/bash
# Cross-platform build script for PolyMorph releases

set -e

echo "Building PolyMorph for multiple platforms..."
echo ""

mkdir -p releases

# ------------------------
# Linux x86_64
# ------------------------
echo "[1/4] Building for Linux x64..."
cargo build --release --target x86_64-unknown-linux-gnu
strip target/x86_64-unknown-linux-gnu/release/polymorph
tar czf releases/polymorph-linux-x64.tar.gz \
    -C target/x86_64-unknown-linux-gnu/release polymorph
echo "✓ Linux x64"

# ------------------------
# Linux ARM64 (aarch64)
# ------------------------
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    echo "[2/4] Building for Linux ARM64 (aarch64)..."
    export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

    cargo build --release --target aarch64-unknown-linux-gnu

    aarch64-linux-gnu-strip \
        target/aarch64-unknown-linux-gnu/release/polymorph

    tar czf releases/polymorph-linux-arm64.tar.gz \
        -C target/aarch64-unknown-linux-gnu/release polymorph

    echo "✓ Linux ARM64"
else
    echo "[2/4] Skipping Linux ARM64 (aarch64 toolchain not installed)"
fi

# ------------------------
# macOS x64
# ------------------------
if rustup target list | grep -q "x86_64-apple-darwin (installed)"; then
    echo "[3/4] Building for macOS x64..."
    cargo build --release --target x86_64-apple-darwin
    tar czf releases/polymorph-macos-x64.tar.gz \
        -C target/x86_64-apple-darwin/release polymorph
    echo "✓ macOS x64"
else
    echo "[3/4] Skipping macOS (target not installed)"
fi

# ------------------------
# Windows x64
# ------------------------
if rustup target list | grep -q "x86_64-pc-windows-gnu (installed)"; then
    echo "[4/4] Building for Windows x64..."
    cargo build --release --target x86_64-pc-windows-gnu
    mkdir -p releases/windows
    cp target/x86_64-pc-windows-gnu/release/polymorph.exe releases/windows/
    (cd releases && zip -r polymorph-windows-x64.zip windows/)
    rm -rf releases/windows
    echo "✓ Windows x64"
else
    echo "[4/4] Skipping Windows (target not installed)"
fi

echo ""
echo "Build complete! Releases in ./releases/"
ls -lh releases/

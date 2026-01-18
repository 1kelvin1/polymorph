#!/bin/bash
# Cross-platform build script for PolyMorph releases

set -e

echo "Building PolyMorph for multiple platforms..."
echo ""

# Linux x64
echo "[1/3] Building for Linux x64..."
cargo build --release --target x86_64-unknown-linux-gnu
strip target/x86_64-unknown-linux-gnu/release/polymorph
mkdir -p releases
tar czf releases/polymorph-linux-x64.tar.gz \
    -C target/x86_64-unknown-linux-gnu/release polymorph
echo "✓ Linux x64: releases/polymorph-linux-x64.tar.gz"

# macOS x64 (requires osxcross or macOS)
if rustup target list | grep -q "x86_64-apple-darwin (installed)"; then
    echo "[2/3] Building for macOS x64..."
    cargo build --release --target x86_64-apple-darwin
    tar czf releases/polymorph-macos-x64.tar.gz \
        -C target/x86_64-apple-darwin/release polymorph
    echo "✓ macOS x64: releases/polymorph-macos-x64.tar.gz"
else
    echo "[2/3] Skipping macOS (target not installed)"
fi

# Windows x64 (requires mingw-w64)
if rustup target list | grep -q "x86_64-pc-windows-gnu (installed)"; then
    echo "[3/3] Building for Windows x64..."
    cargo build --release --target x86_64-pc-windows-gnu
    mkdir -p releases/windows
    cp target/x86_64-pc-windows-gnu/release/polymorph.exe releases/windows/
    (cd releases && zip -r polymorph-windows-x64.zip windows/)
    rm -rf releases/windows
    echo "✓ Windows x64: releases/polymorph-windows-x64.zip"
else
    echo "[3/3] Skipping Windows (target not installed)"
fi

echo ""
echo "Build complete! Releases in ./releases/"
ls -lh releases/

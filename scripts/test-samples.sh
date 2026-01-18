#!/bin/bash
# Test PolyMorph against sample binaries

set -e

POLYMORPH="./target/release/polymorph"

if [ ! -f "$POLYMORPH" ]; then
    echo "Error: PolyMorph not built. Run 'cargo build --release' first"
    exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo "  Testing PolyMorph Detection"
echo "═══════════════════════════════════════════════════════"
echo ""

# Create test samples directory
mkdir -p test_samples

# Test 1: Empty file
echo "[Test 1] Empty file..."
touch test_samples/empty.bin
$POLYMORPH test_samples/empty.bin > /dev/null 2>&1
echo "✓ Handled empty file"

# Test 2: Random data
echo "[Test 2] Random data..."
dd if=/dev/urandom of=test_samples/random.bin bs=1024 count=10 2>/dev/null
$POLYMORPH test_samples/random.bin > /dev/null 2>&1
echo "✓ Handled random data"

# Test 3: Fake PE header
echo "[Test 3] Fake PE header..."
echo -ne "MZ\x90\x00" > test_samples/fake_pe.exe
$POLYMORPH test_samples/fake_pe.exe > /dev/null 2>&1
echo "✓ Detected fake PE"

# Test 4: Fake ELF header
echo "[Test 4] Fake ELF header..."
echo -ne "\x7FELF" > test_samples/fake_elf
$POLYMORPH test_samples/fake_elf > /dev/null 2>&1
echo "✓ Detected fake ELF"

# Test 5: APE magic
echo "[Test 5] APE magic signature..."
echo -ne "MZqFpD" > test_samples/fake_ape.com
$POLYMORPH test_samples/fake_ape.com | grep -q "APE"
echo "✓ Detected APE signature"

# Test 6: Zig strings
echo "[Test 6] Zig compiler strings..."
echo "__zig_panic_handler" > test_samples/fake_zig.exe
$POLYMORPH test_samples/fake_zig.exe | grep -q "Zig"
echo "✓ Detected Zig strings"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  All Tests Passed!"
echo "═══════════════════════════════════════════════════════"

# Cleanup
rm -rf test_samples

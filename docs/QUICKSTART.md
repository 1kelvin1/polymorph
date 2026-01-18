# Quick Start

## Build
```bash
cargo build --release
```

## Scan
```bash
polymorph suspicious.exe
polymorph --json malware.wasm
```

## Exit Codes
- 0: Clean
- 1: Low (0-40)
- 2: Medium (40-60)
- 3: High (60-80)
- 4: Critical (80+)
- 5: Error

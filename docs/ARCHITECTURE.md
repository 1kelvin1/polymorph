# Architecture

## Components
- **Scanner**: Orchestrates detection
- **Detectors**: APE, Zig, WASM, evasion
- **Report**: Human/JSON output
- **Utils**: Formatting, hashing

## Risk Scoring
Risk = Σ(severity) + binary_type_bonus
Max: 100

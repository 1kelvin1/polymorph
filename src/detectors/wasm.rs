use super::{find_pattern, Detection, DetectionCategory, Severity};

const WASM_MAGIC: &[u8] = &[0x00, 0x61, 0x73, 0x6D];
const WASM_VERSION_1: &[u8] = &[0x01, 0x00, 0x00, 0x00];

const SUSPICIOUS_IMPORTS: &[&str] = &[
    "crypto.subtle",
    "crypto.getRandomValues",
    "WebGL",
    "gpu",
    "WebGPU",
    "Worker",
    "SharedArrayBuffer",
    "fetch",
    "XMLHttpRequest",
    "WebSocket",
    "navigator.sendBeacon",
    "document.createElement",
    "eval",
    "Function",
    "document.write",
    "innerHTML",
    "coinhive",
    "cryptonight",
    "monero",
    "xmrig",
];

const CRYPTOMINER_PATTERNS: &[&str] = &["keccak", "sha3", "blake2", "cryptonight", "cn/r"];

pub fn scan_wasm_format(data: &[u8], detections: &mut Vec<Detection>) {
    // detect magic with only 4 bytes present (some tests only provide the magic)
    if data.len() >= 4 && &data[0..4] == WASM_MAGIC {
        detections.push(Detection {
            category: DetectionCategory::WasmBinary,
            severity: Severity::Low,
            description: "WASM (WebAssembly) binary detected".to_string(),
            offset: Some(0),
        });

        // only parse version/sections when we have at least 8 bytes
        if data.len() >= 8 && &data[4..8] == WASM_VERSION_1 {
            scan_wasm_sections(data, detections);
        }
    }
}

pub fn scan_wasm_threats(data: &[u8], detections: &mut Vec<Detection>) {
    if data.len() < 4 || &data[0..4] != WASM_MAGIC {
        return;
    }

    scan_cryptomining_indicators(data, detections);
    scan_suspicious_imports(data, detections);
}

fn scan_wasm_sections(data: &[u8], detections: &mut Vec<Detection>) {
    let mut offset = 8;
    let mut code_size = 0;

    while offset < data.len().saturating_sub(2) {
        offset += 1;
        let size = data.get(offset).copied().unwrap_or(0) as usize;
        offset += 1;

        if data.get(offset.saturating_sub(2)).copied().unwrap_or(0) == 10 {
            code_size += size;
        }

        offset += size;
        if offset >= data.len() {
            break;
        }
    }

    if code_size > 100_000 {
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::Medium,
            description: format!("Large WASM code ({}KB)", code_size / 1024),
            offset: None,
        });
    }
}

fn scan_cryptomining_indicators(data: &[u8], detections: &mut Vec<Detection>) {
    for pattern in CRYPTOMINER_PATTERNS {
        if let Some(offset) = find_pattern(data, pattern.as_bytes()) {
            detections.push(Detection {
                category: DetectionCategory::WasmThreat,
                severity: Severity::High,
                description: format!("Cryptomining: '{}'", pattern),
                offset: Some(offset),
            });
        }
    }

    if find_pattern(data, b"WebGL").is_some() {
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::High,
            description: "GPU API usage detected".to_string(),
            offset: None,
        });
    }
}

fn scan_suspicious_imports(data: &[u8], detections: &mut Vec<Detection>) {
    let mut found_imports = Vec::new();

    for import in SUSPICIOUS_IMPORTS {
        if let Some(offset) = find_pattern(data, import.as_bytes()) {
            found_imports.push(*import);

            detections.push(Detection {
                category: DetectionCategory::WasmThreat,
                severity: Severity::Medium,
                description: format!("Suspicious import: '{}'", import),
                offset: Some(offset),
            });
        }
    }

    // use the collected imports to determine combined heuristics
    let has_network = found_imports
        .iter()
        .any(|i| i.contains("fetch") || i.contains("WebSocket") || i.contains("XMLHttpRequest"));
    let has_crypto = found_imports
        .iter()
        .any(|i| i.contains("crypto") || i.contains("coinhive") || i.contains("cryptonight"));

    if has_network && has_crypto {
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::Critical,
            description: "Network + crypto: possible exfiltration".to_string(),
            offset: None,
        });
    }

    // optional: summary detection if you want a single summary for tests/logging
    if !found_imports.is_empty() {
        detections.push(Detection {
            category: DetectionCategory::WasmThreat,
            severity: Severity::Low,
            description: format!(
                "Found suspicious imports: {} ({} total)",
                found_imports.join(", "),
                found_imports.len()
            ),
            offset: None,
        });
    }
}

use super::{Detection, DetectionCategory, Severity, find_pattern};

const COSMO_SIGNATURES: &[&str] = &[
    "cosmocc", "Actually Portable Executable", "libc/runtime/runtime.h",
    "libc/calls/calls.h", "IsWindows", "IsLinux", "IsXnu", "IsMetal",
    "IsFreebsd", "IsOpenbsd", "cosmo_once", "__init_cosmo",
];

const COSMO_FUNCTIONS: &[&str] = &[
    "IsWindows(", "IsLinux(", "IsXnu(", "IsMetal(",
    "IsFreebsd(", "IsOpenbsd(", "IsNetbsd(",
];

const APE_MAGIC_SIGNATURES: &[&[u8]] = &[
    b"MZqFpD",
    b"\x7fELF",
    b"MZ\x90\x00",
];

pub fn scan_ape_format(data: &[u8], detections: &mut Vec<Detection>) {
    for magic in APE_MAGIC_SIGNATURES {
        if data.len() >= magic.len() && &data[..magic.len()] == *magic {
            detections.push(Detection {
                category: DetectionCategory::APEPolyglot,
                severity: Severity::Medium,
                description: format!("APE magic signature: {:?}", 
                    String::from_utf8_lossy(magic)),
                offset: Some(0),
            });
        }
    }

    let has_pe = find_pattern(data, b"MZ").is_some();
    let has_elf = find_pattern(data, b"\x7fELF").is_some();
    
    if has_pe && has_elf {
        detections.push(Detection {
            category: DetectionCategory::APEPolyglot,
            severity: Severity::High,
            description: "Polyglot binary (PE + ELF), Actually Portable Executable".to_string(),
            offset: None,
        });
    }
}

pub fn scan_cosmo_signatures(data: &[u8], detections: &mut Vec<Detection>) {
    let mut cosmo_count = 0;
    
    for pattern in COSMO_SIGNATURES {
        if let Some(offset) = find_pattern(data, pattern.as_bytes()) {
            cosmo_count += 1;
            detections.push(Detection {
                category: DetectionCategory::CosmoSignature,
                severity: Severity::Low,
                description: format!("Cosmopolitan libc string: '{}'", pattern),
                offset: Some(offset),
            });
        }
    }

    let mut function_count = 0;
    for func in COSMO_FUNCTIONS {
        if find_pattern(data, func.as_bytes()).is_some() {
            function_count += 1;
        }
    }

    if function_count >= 3 {
        detections.push(Detection {
            category: DetectionCategory::CosmoSignature,
            severity: Severity::Medium,
            description: format!("Multiple OS detection functions ({}), polyglot capabilities", function_count),
            offset: None,
        });
    }

    if cosmo_count >= 4 {
        detections.push(Detection {
            category: DetectionCategory::CosmoSignature,
            severity: Severity::High,
            description: format!("Strong Cosmopolitan libc indicators ({}), APE binary confirmed", cosmo_count),
            offset: None,
        });
    }
}

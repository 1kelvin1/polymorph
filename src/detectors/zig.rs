use super::{Detection, DetectionCategory, Severity, find_pattern};

const ZIG_SIGNATURES: &[&[u8]] = &[
    b"zig version",
    b"std.zig",
    b"builtin.zig",
    b"zig_backend",
];

const ZIG_PANIC_HANDLERS: &[&[u8]] = &[
    b"reached unreachable code",
    b"panic: ",
    b"@panic",
];

const ZIG_STDLIB: &[&[u8]] = &[
    b"std.os.windows",
    b"std.os.linux",
    b"std.debug.assert",
];

pub fn scan_zig_signatures(data: &[u8], detections: &mut Vec<Detection>) {
    let mut sig_count = 0;

    for sig in ZIG_SIGNATURES {
        if let Some(offset) = find_pattern(data, sig) {
            sig_count += 1;
            detections.push(Detection {
                category: DetectionCategory::ZigSignature,
                severity: Severity::Medium,
                description: format!("Zig compiler signature: '{}'", String::from_utf8_lossy(sig)),
                offset: Some(offset),
            });
        }
    }

    for handler in ZIG_PANIC_HANDLERS {
        if find_pattern(data, handler).is_some() {
            sig_count += 1;
        }
    }

    for lib in ZIG_STDLIB {
        if find_pattern(data, lib).is_some() {
            sig_count += 1;
        }
    }

    if sig_count >= 3 {
        detections.push(Detection {
            category: DetectionCategory::ZigSignature,
            severity: Severity::High,
            description: format!("Strong Zig compiler indicators ({})", sig_count),
            offset: None,
        });
    }
}

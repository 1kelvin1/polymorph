pub mod zig;
pub mod ape;
pub mod polyglot;
pub mod evasion;
pub mod wasm;  // NEW

use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub struct Detection {
    pub category: DetectionCategory,
    pub severity: Severity,
    pub description: String,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DetectionCategory {
    ZigSignature,
    CosmoSignature,
    APEPolyglot,
    DirectSyscall,
    AntiDebug,
    AntiVM,
    StringObfuscation,
    ProcessInjection,
    Suspicious,
    WasmBinary,      // NEW
    WasmThreat,      // NEW
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_val = match self {
            Severity::Low => 0,
            Severity::Medium => 1,
            Severity::High => 2,
            Severity::Critical => 3,
        };
        let other_val = match other {
            Severity::Low => 0,
            Severity::Medium => 1,
            Severity::High => 2,
            Severity::Critical => 3,
        };
        self_val.cmp(&other_val)
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BinaryType {
    Unknown,
    Zig,
    Cosmopolitan,
    Hybrid,
    Wasm,            // NEW
    Generic,
}

pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

pub fn calculate_risk_score(detections: &[Detection], binary_type: &BinaryType) -> u32 {
    let mut score = 0u32;
    
    for detection in detections {
        score += match detection.severity {
            Severity::Low => 5,
            Severity::Medium => 15,
            Severity::High => 25,
            Severity::Critical => 40,
        };
    }
    
    // Binary type bonuses
    if *binary_type == BinaryType::Cosmopolitan {
        score += 10;
    }
    if *binary_type == BinaryType::Hybrid {
        score += 20;
    }
    if *binary_type == BinaryType::Wasm {
        score += 5;  // WASM less suspicious by default (common in web)
    }
    
    score.min(100)
}

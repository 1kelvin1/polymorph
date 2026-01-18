use crate::detectors::*;

pub struct Scanner {
    pub binary_data: Vec<u8>,
    pub detections: Vec<Detection>,
    pub binary_type: BinaryType,
}

impl Scanner {
    pub fn new(binary_data: Vec<u8>) -> Self {
        Self {
            binary_data,
            detections: Vec::new(),
            binary_type: BinaryType::Unknown,
        }
    }

    pub fn run_full_scan(&mut self, verbose: bool) {
        // Check for WASM first (distinctive magic bytes)
        if verbose { println!("[*] Checking for WebAssembly format..."); }
        wasm::scan_wasm_format(&self.binary_data, &mut self.detections);
        
        // If WASM, run WASM-specific threat detection
        let is_wasm = self.binary_data.len() >= 4 && 
                      &self.binary_data[0..4] == &[0x00, 0x61, 0x73, 0x6D];
        
        if is_wasm {
            if verbose { println!("[*] Running WASM threat analysis..."); }
            wasm::scan_wasm_threats(&self.binary_data, &mut self.detections);
        }
        
        // Continue with other detections (polyglot possibilities)
        if verbose { println!("[*] Scanning for APE polyglot format..."); }
        ape::scan_ape_format(&self.binary_data, &mut self.detections);
        
        if verbose { println!("[*] Scanning for Cosmopolitan signatures..."); }
        ape::scan_cosmo_signatures(&self.binary_data, &mut self.detections);
        
        if verbose { println!("[*] Scanning for Zig signatures..."); }
        zig::scan_zig_signatures(&self.binary_data, &mut self.detections);
        
        if verbose { println!("[*] Scanning for direct syscalls..."); }
        evasion::scan_direct_syscalls(&self.binary_data, &mut self.detections);
        
        if verbose { println!("[*] Scanning for anti-analysis techniques..."); }
        evasion::scan_anti_analysis(&self.binary_data, &mut self.detections);
        
        if verbose { println!("[*] Scanning for process injection..."); }
        evasion::scan_process_injection(&self.binary_data, &mut self.detections);
        
        if verbose { println!("[*] Analyzing entropy..."); }
        polyglot::scan_entropy_anomalies(&self.binary_data, &mut self.detections);
        
        self.classify_binary();
    }

    fn classify_binary(&mut self) {
        let has_zig = self.detections.iter().any(|d| d.category == DetectionCategory::ZigSignature);
        let has_cosmo = self.detections.iter().any(|d| 
            d.category == DetectionCategory::CosmoSignature || 
            d.category == DetectionCategory::APEPolyglot
        );
        let has_wasm = self.detections.iter().any(|d| 
            d.category == DetectionCategory::WasmBinary
        );

        self.binary_type = if has_wasm {
            BinaryType::Wasm
        } else if has_zig && has_cosmo {
            BinaryType::Hybrid
        } else if has_zig {
            BinaryType::Zig
        } else if has_cosmo {
            BinaryType::Cosmopolitan
        } else {
            BinaryType::Generic
        };
    }
}

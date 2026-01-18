use super::{Detection, DetectionCategory, Severity, find_pattern};

const DYNAMIC_SYSCALL_INDICATORS: &[&str] = &[
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    "NtCreateThreadEx", "NtWriteVirtualMemory", "NtOpenProcess",
];

const EVASION_STRINGS: &[&str] = &[
    "BeingDebugged", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "VBOX", "VMWARE", "VirtualBox", "QEMU",
];

const INJECTION_APIS: &[&str] = &[
    "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
    "CreateRemoteThread", "NtCreateThreadEx", "ptrace", "task_for_pid",
];

pub fn scan_direct_syscalls(data: &[u8], detections: &mut Vec<Detection>) {
    let syscall_stubs = find_syscall_stubs(data);
    
    if syscall_stubs.len() > 3 {
        detections.push(Detection {
            category: DetectionCategory::DirectSyscall,
            severity: Severity::High,
            description: format!("Multiple direct syscall stubs ({}), likely EDR evasion", syscall_stubs.len()),
            offset: None,
        });

        let mut nt_functions = 0;
        for indicator in DYNAMIC_SYSCALL_INDICATORS {
            if find_pattern(data, indicator.as_bytes()).is_some() {
                nt_functions += 1;
            }
        }

        if nt_functions >= 3 {
            detections.push(Detection {
                category: DetectionCategory::DirectSyscall,
                severity: Severity::Critical,
                description: format!("Dynamic syscall resolution ({} Nt functions), Hell's Gate/Halo's Gate", nt_functions),
                offset: None,
            });
        }
    }
}

pub fn scan_anti_analysis(data: &[u8], detections: &mut Vec<Detection>) {
    let mut evasion_count = 0;
    
    for evasion_str in EVASION_STRINGS {
        if let Some(offset) = find_pattern(data, evasion_str.as_bytes()) {
            evasion_count += 1;
            
            let category = if evasion_str.contains("VBOX") || 
                              evasion_str.contains("VMWARE") ||
                              evasion_str.contains("QEMU") {
                DetectionCategory::AntiVM
            } else {
                DetectionCategory::AntiDebug
            };

            detections.push(Detection {
                category,
                severity: Severity::Medium,
                description: format!("Evasion technique: '{}'", evasion_str),
                offset: Some(offset),
            });
        }
    }

    if evasion_count >= 4 {
        detections.push(Detection {
            category: DetectionCategory::Suspicious,
            severity: Severity::High,
            description: format!("Multiple evasion techniques ({}), strong malware indicator", evasion_count),
            offset: None,
        });
    }
}

pub fn scan_process_injection(data: &[u8], detections: &mut Vec<Detection>) {
    let mut found_apis = Vec::new();
    
    for api in INJECTION_APIS {
        if find_pattern(data, api.as_bytes()).is_some() {
            found_apis.push(*api);
        }
    }

    if found_apis.len() >= 3 {
        detections.push(Detection {
            category: DetectionCategory::ProcessInjection,
            severity: Severity::Critical,
            description: format!("Process injection API chain: {:?}", found_apis),
            offset: None,
        });
    }
}

fn find_syscall_stubs(data: &[u8]) -> Vec<usize> {
    let mut stubs = Vec::new();
    
    for i in 0..data.len().saturating_sub(10) {
        if data[i..].len() >= 10 &&
           data[i] == 0x4C && data[i+1] == 0x8B && data[i+2] == 0xD1 &&
           data[i+3] == 0xB8 &&
           data[i+8] == 0x0F && data[i+9] == 0x05 {
            stubs.push(i);
        }
    }
    
    stubs
}

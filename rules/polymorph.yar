/*
    PolyMorph YARA Rules v1.0
    Comprehensive detection for APE and Zig malware
    
    Usage:
        yara -r polymorph.yar /path/to/scan
        yara -s polymorph.yar suspicious.exe
*/

import "pe"
import "elf"

// ============================================================================
// APE (Actually Portable Executable) Detection
// ============================================================================

rule APE_Cosmopolitan_Binary {
    meta:
        description = "Detects Cosmopolitan Actually Portable Executable"
        author = "PolyMorph Project"
        date = "2026-01-16"
        severity = "medium"
        category = "polyglot"
        reference = "https://github.com/jart/cosmopolitan"
    
    strings:
        // APE magic signature
        $ape_magic = "MZqFpD"
        
        // Cosmopolitan libc signatures
        $cosmo1 = "IsWindows" ascii
        $cosmo2 = "IsLinux" ascii
        $cosmo3 = "IsXnu" ascii
        $cosmo4 = "IsMetal" ascii
        $cosmo5 = "IsFreebsd" ascii
        $cosmo6 = "IsOpenbsd" ascii
        $cosmo7 = "cosmopolitan" nocase ascii
        $cosmo8 = "cosmocc" ascii
        $cosmo9 = "libc/runtime/runtime.h" ascii
        
        // PE and ELF headers
        $pe_header = { 4D 5A }
        $elf_header = { 7F 45 4C 46 }
    
    condition:
        // APE magic at start
        ($ape_magic at 0) or
        
        // Polyglot structure: PE + ELF + Cosmo signatures
        (($pe_header at 0 and $elf_header) and 2 of ($cosmo*))
}

rule APE_Malware_High_Confidence {
    meta:
        description = "High-confidence APE malware with evasion techniques"
        author = "PolyMorph Project"
        severity = "critical"
        category = "malware"
    
    strings:
        // Cosmopolitan detection
        $cosmo1 = "IsWindows" ascii
        $cosmo2 = "IsLinux" ascii
        $cosmo3 = "IsXnu" ascii
        
        // Cross-platform injection APIs
        $inject_win = "CreateRemoteThread" ascii
        $inject_linux = "ptrace" ascii
        $inject_macos = "task_for_pid" ascii
        $inject_write = "WriteProcessMemory" ascii
        $inject_alloc = "VirtualAllocEx" ascii
        
        // Evasion techniques
        $evasion1 = "BeingDebugged" ascii
        $evasion2 = "IsDebuggerPresent" ascii
        $evasion3 = "VBOX" nocase ascii
        $evasion4 = "VMWARE" nocase ascii
        $evasion5 = "QEMU" nocase ascii
    
    condition:
        // Cosmopolitan + Cross-platform injection + Evasion
        (2 of ($cosmo*)) and 
        (2 of ($inject*)) and 
        (1 of ($evasion*))
}

rule APE_Polyglot_Structure {
    meta:
        description = "Detects polyglot binary structure (PE + ELF)"
        author = "PolyMorph Project"
        severity = "high"
        category = "polyglot"
    
    strings:
        $pe = "MZ"
        $elf = { 7F 45 4C 46 }
        $macho = { FE ED FA CE }
        $macho64 = { FE ED FA CF }
    
    condition:
        // Multiple executable formats in same file
        (($pe at 0) and ($elf or $macho or $macho64))
}

// ============================================================================
// Zig Malware Detection
// ============================================================================

rule Zig_Compiler_Artifacts {
    meta:
        description = "Detects Zig compiler artifacts in binary"
        author = "PolyMorph Project"
        severity = "low"
        category = "language_detection"
    
    strings:
        $zig1 = "zig version" ascii
        $zig2 = "std.builtin" ascii
        $zig3 = "std.debug" ascii
        $zig4 = "__zig_" ascii
        $zig5 = "panic: " ascii
        $zig6 = "reached unreachable code" ascii
    
    condition:
        2 of them
}

rule Zig_Direct_Syscalls_HellsGate {
    meta:
        description = "Zig malware with direct syscalls (Hell's Gate technique)"
        author = "PolyMorph Project"
        severity = "critical"
        category = "evasion"
        reference = "https://vxug.fakedoma.in/papers/HellsGate.pdf"
    
    strings:
        // Zig signatures
        $zig1 = "__zig_" ascii
        $zig2 = "std.builtin" ascii
        
        // NT functions (dynamic syscall resolution)
        $nt1 = "NtAllocateVirtualMemory" ascii
        $nt2 = "NtProtectVirtualMemory" ascii
        $nt3 = "NtCreateThreadEx" ascii
        $nt4 = "NtWriteVirtualMemory" ascii
        $nt5 = "NtOpenProcess" ascii
        
        // Direct syscall stub pattern (x64)
        // mov r10, rcx; mov eax, <syscall_num>; syscall; ret
        $syscall_stub = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3 }
    
    condition:
        (1 of ($zig*)) and 
        (2 of ($nt*)) and 
        (#syscall_stub > 2)
}

rule Zig_Malware_Process_Injection {
    meta:
        description = "Zig malware with process injection capabilities"
        author = "PolyMorph Project"
        severity = "high"
        category = "injection"
    
    strings:
        $zig = "__zig_" ascii
        
        // Windows injection
        $inject1 = "OpenProcess" ascii
        $inject2 = "VirtualAllocEx" ascii
        $inject3 = "WriteProcessMemory" ascii
        $inject4 = "CreateRemoteThread" ascii
        $inject5 = "NtCreateThreadEx" ascii
    
    condition:
        $zig and (3 of ($inject*))
}

// ============================================================================
// Generic Evasion Techniques
// ============================================================================

rule Anti_Debug_Techniques {
    meta:
        description = "Multiple anti-debugging techniques detected"
        author = "PolyMorph Project"
        severity = "medium"
        category = "evasion"
    
    strings:
        $debug1 = "BeingDebugged" ascii
        $debug2 = "IsDebuggerPresent" ascii
        $debug3 = "CheckRemoteDebuggerPresent" ascii
        $debug4 = "NtQueryInformationProcess" ascii
        $debug5 = "OutputDebugString" ascii
        $debug6 = "DebugActiveProcess" ascii
        
        // PEB access (BeingDebugged flag check)
        $peb_check = { 65 48 8B ?? 25 ?? ?? ?? ?? 48 8B ?? ?? 80 ?? ?? ?? 75 }
    
    condition:
        3 of them
}

rule Anti_VM_Sandbox_Detection {
    meta:
        description = "VM and sandbox detection strings"
        author = "PolyMorph Project"
        severity = "medium"
        category = "evasion"
    
    strings:
        $vm1 = "VBOX" nocase ascii
        $vm2 = "VMWARE" nocase ascii
        $vm3 = "VirtualBox" nocase ascii
        $vm4 = "QEMU" nocase ascii
        $vm5 = "Xen" nocase ascii
        $vm6 = "VMW" ascii
        $vm7 = "Parallels" nocase ascii
        $vm8 = "vmmouse" nocase ascii
        $vm9 = "vmhgfs" nocase ascii
        
        // VM registry keys
        $reg1 = "SOFTWARE\\VMware" nocase ascii
        $reg2 = "HARDWARE\\ACPI\\DSDT\\VBOX" nocase ascii
    
    condition:
        3 of them
}

rule Direct_Syscall_Pattern {
    meta:
        description = "Direct syscall patterns (EDR evasion)"
        author = "PolyMorph Project"
        severity = "high"
        category = "evasion"
    
    strings:
        // x64 syscall stub: mov r10,rcx; mov eax,<num>; syscall
        $stub1 = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }
        
        // Alternative patterns
        $stub2 = { 49 89 CA B8 ?? ?? ?? ?? 0F 05 }
        $stub3 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }
    
    condition:
        (#stub1 > 3) or (#stub2 > 3) or (#stub3 > 3)
}

rule Hell_Gate_Halo_Gate_Technique {
    meta:
        description = "Hell's Gate / Halo's Gate dynamic syscall resolution"
        author = "PolyMorph Project"
        severity = "critical"
        category = "advanced_evasion"
        reference = "https://vxug.fakedoma.in/papers/HellsGate.pdf"
    
    strings:
        // NT function names
        $nt1 = "NtAllocateVirtualMemory" ascii
        $nt2 = "NtProtectVirtualMemory" ascii
        $nt3 = "NtCreateThreadEx" ascii
        $nt4 = "NtWriteVirtualMemory" ascii
        
        // Syscall stubs
        $syscall = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }
        
        // ntdll.dll references (for parsing)
        $ntdll = "ntdll.dll" nocase ascii
    
    condition:
        (3 of ($nt*)) and (#syscall > 2) and $ntdll
}

// ============================================================================
// String Obfuscation Detection
// ============================================================================

rule XOR_String_Obfuscation {
    meta:
        description = "XOR-based string obfuscation detected"
        author = "PolyMorph Project"
        severity = "medium"
        category = "obfuscation"
    
    strings:
        // XOR deobfuscation loops (x64)
        $xor_loop1 = { 8A ?? ?? 34 ?? 88 ?? ?? 48 FF C? }
        $xor_loop2 = { 30 ?? 48 FF C? 48 ?? ?? 7? }
        $xor_loop3 = { 80 ?? ?? 48 FF C? 48 3? ?? 7? }
    
    condition:
        any of them
}

// ============================================================================
// Combined High-Risk Patterns
// ============================================================================

rule Polyglot_Malware_Combined {
    meta:
        description = "Combined polyglot malware indicators"
        author = "PolyMorph Project"
        severity = "critical"
        category = "malware"
    
    strings:
        // Polyglot indicators
        $pe = "MZ"
        $elf = { 7F 45 4C 46 }
        $cosmo = /Is(Windows|Linux|Xnu)/
        
        // Malicious capabilities
        $inject = /(CreateRemoteThread|WriteProcessMemory|ptrace|task_for_pid)/
        $evasion = /(BeingDebugged|VBOX|VMWARE)/
        
        // Direct syscalls
        $syscall = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }
    
    condition:
        // Polyglot + Injection + Evasion + Syscalls
        (($pe at 0) and $elf) and 
        $cosmo and 
        $inject and 
        $evasion and 
        (#syscall > 1)
}

rule APE_or_Zig_with_Malicious_Behavior {
    meta:
        description = "APE or Zig binary with suspicious behavior"
        author = "PolyMorph Project"
        severity = "high"
        category = "suspicious"
    
    strings:
        // APE/Zig indicators
        $lang1 = "IsWindows" ascii
        $lang2 = "__zig_" ascii
        
        // Suspicious strings
        $sus1 = "cmd.exe" ascii
        $sus2 = "powershell" nocase ascii
        $sus3 = "/bin/sh" ascii
        $sus4 = "127.0.0.1" ascii
        $sus5 = "malware" nocase ascii
        $sus6 = "exploit" nocase ascii
        
        // Network activity
        $net1 = "HttpSendRequest" ascii
        $net2 = "InternetOpen" ascii
        $net3 = "socket" ascii
        $net4 = "connect" ascii
    
    condition:
        (1 of ($lang*)) and 
        (2 of ($sus*) or 2 of ($net*))
}

// ============================================================================
// WebAssembly (WASM) Malware Detection
// ============================================================================

rule WASM_Binary_Format {
    meta:
        description = "Detects WebAssembly binary format"
        author = "PolyMorph Project"
        severity = "low"
        category = "wasm"
    
    strings:
        $wasm_magic = { 00 61 73 6D }  // \0asm
        $wasm_version = { 01 00 00 00 }
    
    condition:
        $wasm_magic at 0 and $wasm_version at 4
}

rule WASM_Cryptominer {
    meta:
        description = "Browser-based cryptocurrency miner in WASM"
        author = "PolyMorph Project"
        severity = "critical"
        category = "cryptominer"
    
    strings:
        $wasm = { 00 61 73 6D }
        
        // Hash function signatures
        $hash1 = "keccak" ascii
        $hash2 = "sha3" ascii
        $hash3 = "cryptonight" ascii
        $hash4 = "cn/" ascii
        $hash5 = "blake2" ascii
        
        // GPU mining
        $gpu1 = "WebGL" ascii
        $gpu2 = "WebGPU" ascii
        $gpu3 = "gpu" ascii
        
        // Multi-threading
        $thread1 = "Worker" ascii
        $thread2 = "SharedArrayBuffer" ascii
        
        // Known miners
        $miner1 = "coinhive" nocase ascii
        $miner2 = "cryptoloot" nocase ascii
        $miner3 = "coinmp" nocase ascii
        $miner4 = "xmrig" nocase ascii
    
    condition:
        $wasm at 0 and (
            (2 of ($hash*)) or
            (1 of ($gpu*) and 1 of ($thread*)) or
            (1 of ($miner*))
        )
}

rule WASM_Obfuscated {
    meta:
        description = "Obfuscated WebAssembly binary"
        author = "PolyMorph Project"
        severity = "high"
        category = "obfuscation"
    
    strings:
        $wasm = { 00 61 73 6D }
        
        // Obfuscation patterns
        $obf1 = "_0x" ascii
        $obf2 = "$$" ascii
        $obf3 = "eval" ascii
        $obf4 = "Function" ascii
        $obf5 = "atob" ascii
    
    condition:
        $wasm at 0 and 3 of ($obf*)
}

rule WASM_Network_Exfiltration {
    meta:
        description = "WASM with network + crypto capabilities"
        author = "PolyMorph Project"
        severity = "critical"
        category = "exfiltration"
    
    strings:
        $wasm = { 00 61 73 6D }
        
        // Network APIs
        $net1 = "fetch" ascii
        $net2 = "XMLHttpRequest" ascii
        $net3 = "WebSocket" ascii
        $net4 = "sendBeacon" ascii
        
        // Crypto APIs
        $crypto1 = "crypto.subtle" ascii
        $crypto2 = "crypto.getRandomValues" ascii
        $crypto3 = "btoa" ascii
    
    condition:
        $wasm at 0 and 
        (1 of ($net*)) and 
        (1 of ($crypto*))
}

rule WASM_Large_Payload {
    meta:
        description = "Unusually large WASM binary for web context"
        author = "PolyMorph Project"
        severity = "medium"
        category = "suspicious"
    
    strings:
        $wasm = { 00 61 73 6D }
    
    condition:
        $wasm at 0 and filesize > 1MB
}

rule WASM_DOM_Manipulation {
    meta:
        description = "WASM with extensive DOM manipulation"
        author = "PolyMorph Project"
        severity = "medium"
        category = "suspicious"
    
    strings:
        $wasm = { 00 61 73 6D }
        
        $dom1 = "document.createElement" ascii
        $dom2 = "document.write" ascii
        $dom3 = "innerHTML" ascii
        $dom4 = "appendChild" ascii
        $dom5 = "eval" ascii
    
    condition:
        $wasm at 0 and 3 of ($dom*)
}

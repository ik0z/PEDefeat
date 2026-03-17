/*
 * PEDefeat — Malware Dev Detection Point Rules
 * Author: Khaled M. Alshammri | @ik0z
 *
 * These rules detect common patterns that AV/EDR flag.
 * Use PEDefeat to identify which rules match YOUR binary,
 * then address each detection point.
 */

rule Shellcode_PEB_Walk_x64 {
    meta:
        description = "x64 PEB access via GS segment (gs:[0x60])"
        severity = "CRITICAL"
        category = "shellcode"
        fix = "Use indirect syscalls or hash-based resolution instead"
    strings:
        $peb64 = { 65 48 8B 04 25 60 00 00 00 }
    condition:
        $peb64
}

rule Shellcode_PEB_Walk_x86 {
    meta:
        description = "x86 PEB access via FS segment (fs:[0x30])"
        severity = "CRITICAL"
        category = "shellcode"
        fix = "Use indirect syscalls or hash-based resolution instead"
    strings:
        $peb32 = { 64 A1 30 00 00 00 }
    condition:
        $peb32
}

rule Syscall_Instruction_Direct {
    meta:
        description = "Direct syscall instruction found"
        severity = "HIGH"
        category = "evasion"
        fix = "Use RecycledGate — jump to ntdll syscall;ret gadget"
    strings:
        $syscall = { 0F 05 }
        $sysenter = { 0F 34 }
        $int2e = { CD 2E }
    condition:
        (#syscall > 3) or $sysenter or $int2e
}

rule Syscall_Stub_Pattern {
    meta:
        description = "SSN resolution stub (mov r10,rcx; mov eax,SSN; syscall)"
        severity = "HIGH"
        category = "evasion"
        fix = "Encrypt stub, use RecycledGate gadgets"
    strings:
        $stub = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 }
    condition:
        $stub
}

rule AMSI_Bypass_Strings {
    meta:
        description = "AMSI bypass function names in binary"
        severity = "CRITICAL"
        category = "evasion"
        fix = "XOR encrypt or use compile-time string encryption (CS macro)"
    strings:
        $amsi1 = "AmsiScanBuffer" ascii wide
        $amsi2 = "AmsiInitialize" ascii wide
        $amsi3 = "AmsiOpenSession" ascii wide
        $amsi4 = "amsi.dll" ascii wide nocase
    condition:
        any of them
}

rule ETW_Bypass_Strings {
    meta:
        description = "ETW bypass function names in binary"
        severity = "CRITICAL"
        category = "evasion"
        fix = "XOR encrypt or use DJB2 hash resolution"
    strings:
        $etw1 = "EtwEventWrite" ascii wide
        $etw2 = "NtTraceEvent" ascii wide
        $etw3 = "EtwpEventWriteFull" ascii wide
    condition:
        any of them
}

rule Injection_API_Combo {
    meta:
        description = "Classic process injection API combination in IAT"
        severity = "CRITICAL"
        category = "injection"
        fix = "Hash-resolve APIs, use indirect syscalls, remove from IAT"
    strings:
        $va = "VirtualAllocEx" ascii
        $wp = "WriteProcessMemory" ascii
        $ct = "CreateRemoteThread" ascii
        $nwvm = "NtWriteVirtualMemory" ascii
        $ncte = "NtCreateThreadEx" ascii
    condition:
        ($va and $wp and $ct) or ($va and $nwvm) or $ncte
}

rule Reflective_DLL_Loader {
    meta:
        description = "Reflective DLL loading export or pattern"
        severity = "CRITICAL"
        category = "loader"
        fix = "Rename export, use ordinal-only export, or use different loading technique"
    strings:
        $ref1 = "ReflectiveLoader" ascii
        $ref2 = "_ReflectiveLoader@4" ascii
        $ref3 = "reflective" ascii nocase
    condition:
        any of them
}

rule C2_Framework_Indicators {
    meta:
        description = "Known C2 framework strings detected"
        severity = "CRITICAL"
        category = "c2"
        fix = "Remove all framework strings, use compile-time XOR encryption"
    strings:
        $cs1 = "beacon" ascii nocase
        $cs2 = "cobalt" ascii nocase
        $met1 = "meterpreter" ascii nocase
        $met2 = "metasploit" ascii nocase
        $mim1 = "mimikatz" ascii nocase
        $mim2 = "Invoke-Mimikatz" ascii nocase
        $hav1 = "havoc" ascii nocase
        $sl1 = "sliver" ascii nocase
    condition:
        any of them
}

rule RWX_Memory_Section {
    meta:
        description = "PE section with Read+Write+Execute permissions"
        severity = "CRITICAL"
        category = "section"
        fix = "Use RW→RX two-stage: allocate RW, write, then protect to RX"
    condition:
        for any section in pe.sections : (
            (section.characteristics & 0xE0000000) == 0xE0000000
        )
}

rule High_Entropy_Section {
    meta:
        description = "PE section with entropy > 7.0 (likely encrypted/packed)"
        severity = "HIGH"
        category = "packer"
        fix = "Use entropy management — interleave null bytes, add low-entropy padding"
    condition:
        for any section in pe.sections : (
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.0
        )
}

rule Credential_Dump_APIs {
    meta:
        description = "Credential harvesting API imports"
        severity = "CRITICAL"
        category = "creds"
        fix = "Hash-resolve all credential APIs, remove from IAT"
    strings:
        $sam1 = "SamConnect" ascii
        $lsa1 = "LsaEnumerateLogonSessions" ascii
        $lsa2 = "LsaGetLogonSessionData" ascii
        $cred1 = "CredEnumerateA" ascii
        $cred2 = "CredEnumerateW" ascii
    condition:
        any of them
}

rule Anti_Debug_Techniques {
    meta:
        description = "Anti-debug API/technique detected"
        severity = "MEDIUM"
        category = "antidebug"
        fix = "If needed, use PEB checks or timing via hash-resolved APIs"
    strings:
        $ad1 = "IsDebuggerPresent" ascii
        $ad2 = "CheckRemoteDebuggerPresent" ascii
        $ad3 = "NtQueryInformationProcess" ascii
        $ad4 = "NtSetInformationThread" ascii
        $ad5 = "OutputDebugStringA" ascii
    condition:
        2 of them
}

rule Packer_Section_Names {
    meta:
        description = "Known packer section names"
        severity = "CRITICAL"
        category = "packer"
        fix = "Use custom packer or rename sections to standard names"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $vmp0 = ".vmp0" ascii
        $vmp1 = ".vmp1" ascii
        $thm = ".themida" ascii
        $asp = ".aspack" ascii
        $enig = ".enigma" ascii
    condition:
        any of them
}

rule Plaintext_URLs_IPs {
    meta:
        description = "Plaintext URLs or IP addresses in binary"
        severity = "HIGH"
        category = "network"
        fix = "XOR encrypt all network indicators, resolve at runtime"
    strings:
        $http = "http://" ascii wide
        $https = "https://" ascii wide
        $ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii wide
    condition:
        (#http + #https > 2) or (#ip > 3)
}

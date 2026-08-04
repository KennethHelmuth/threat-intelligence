rule backdoor_vshell_x64_1_13127_classic_
{
    meta:
        description = "Auto-generated stub for backdoor_vshell/x64!1_13127_(classic) based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-04"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_vshell/x64!1_13127_(classic)"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 5ce81ed3419f9057c86686b522d2474913a5a70a0401f5795b460b6feed2c198

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

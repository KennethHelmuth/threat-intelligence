rule backdoor_linux_flmc
{
    meta:
        description = "Auto-generated stub for backdoor_linux_flmc based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-16"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "backdoor_linux_flmc"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // cfa99a415781c0e1748d2b679043c9ada2f9555d584f76fdfcd77aea88a01752

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

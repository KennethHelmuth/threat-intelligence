rule npm_compromise
{
    meta:
        description = "Auto-generated stub for npm_compromise based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-11"
        version     = "1.0"
        source      = "OTX"
        family      = "npm_compromise"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0
        // 9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule ermac
{
    meta:
        description = "Auto-generated stub for ermac based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-26"
        version     = "1.0"
        source      = "OTX"
        family      = "ermac"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0452650b0b1e7eeaf01bd74e927a4dd7
        // 90a61dcc76d704b2e861a0465ced2f87

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

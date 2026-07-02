rule win_hijackloader_20260702
{
    meta:
        description = "Auto-generated stub for win.hijackloader based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-02"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.hijackloader"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c31217109ba50059d7c081a7e832d0cf
        // 9c0a88ea53c4e0324157542385a1d342101feb51cf7b8cf76e9441376f1f522a

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

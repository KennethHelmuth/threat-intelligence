rule win_salatstealer_20260826
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // e7722735a7128302b1c430d18a602917
        // d83f465bde16528aebdff1e523a46613a97a32234712fe4e9ef29d6a979a72f6
        // 982793e92a09243ed66c378aad812825
        // c02e2b1e61535024d4d7b829adf747907fb719bcb19560d753b0f6b10a95b0d8

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

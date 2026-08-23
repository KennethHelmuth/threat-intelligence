rule win_arkei_stealer_20260823
{
    meta:
        description = "Auto-generated stub for win.arkei_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-23"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.arkei_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 1158797c8d9ef2696029b1d82e8a9515
        // e3ecc6938dd5234a75a8fda454717bba20897d6aa12b9a324b5f81305d1f7d66

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

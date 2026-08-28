rule win_salatstealer_20260828
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-28"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 4fc957b553122ec20e29a91606b8196794e31df4f5966fcf72faae5350b6a852
        // 71d31fe49361d515a5bf77bce5a109f8

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

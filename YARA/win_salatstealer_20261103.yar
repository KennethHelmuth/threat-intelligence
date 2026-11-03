rule win_salatstealer_20261103
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-03"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6
        // 383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_coinminer_20261128
{
    meta:
        description = "Auto-generated stub for win.coinminer based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-28"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.coinminer"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 60801e36286950ca4bf9fa8334273f92c45203e2ec928b0c3384e3cd831acd61

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_coinminer_20261114
{
    meta:
        description = "Auto-generated stub for win.coinminer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-14"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.coinminer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // d48d8c87335633e9ccf35f6b2fcae5146cc357194ec3d9b4e74b94549b759a25
        // 60b22e07cd80d6171889f3a027168bb33dac7b7316223d4678bcf6d7f919d12e

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

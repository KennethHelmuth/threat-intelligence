rule win_termite
{
    meta:
        description = "Auto-generated stub for win.termite based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-27"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.termite"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 2cae63ea97507418aec97137f6080e73
        // 4c58195328f5b5e4a37aa6f42b386172
        // 6b06aae5ec596cdbc1b9d4c457fd5f81

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_stealc_20260701
{
    meta:
        description = "Auto-generated stub for win.stealc based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-01"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c3635ad319d02c61c07dd3095b4998cf81c6d1e361284fcb67d00fe8b01d1e38
        // 55a77ff1a1fca2d0a2bbf1c5b6d9b6db

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

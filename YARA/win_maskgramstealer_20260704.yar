rule win_maskgramstealer_20260704
{
    meta:
        description = "Auto-generated stub for win.maskgramstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-04"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.maskgramstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c1cc183b4feb7f01efb4e39d1465c323
        // 0275c6cf588a7e26e97cbd3a8d301370ebeb18470e86b21d295c8d93ca778d86

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

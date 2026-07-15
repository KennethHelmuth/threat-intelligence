rule win_phantom_stealer_20260715
{
    meta:
        description = "Auto-generated stub for win.phantom_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-15"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.phantom_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // b7e5d882f64df87f2d70b9df4df1033f
        // 03ff10f626253ac8613b7c489170d602c524b9e8b69ebc13d677a800b0bdb0db

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

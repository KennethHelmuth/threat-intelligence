rule win_void
{
    meta:
        description = "Auto-generated stub for win.void based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-14"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.void"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 36612c13573375fb4c796f3569eb50c0
        // d0319eb0aad677d46a509fdcdf2c03e7c92cee9794cee70a79d3e84c564708c0

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

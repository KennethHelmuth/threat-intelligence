rule win_maskgramstealer
{
    meta:
        description = "Auto-generated stub for win.maskgramstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.maskgramstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 6a0dfb7d51c8caed596fa2b89cdedf7180a86f09c4aba4e5bb43d03fd1b9d255
        // 5cdded78f2b177c4245ffb1778b6491f

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

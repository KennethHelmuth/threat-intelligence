rule win_remcos
{
    meta:
        description = "Auto-generated stub for win.remcos based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-25"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.remcos"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 363ee51fc02f20cb206039434758c3afa1c71bc7d316c6db4a39b0d310ab92f9

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

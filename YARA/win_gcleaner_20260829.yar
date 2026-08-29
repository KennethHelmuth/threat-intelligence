rule win_gcleaner_20260829
{
    meta:
        description = "Auto-generated stub for win.gcleaner based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.gcleaner"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 801e7911d8ef33ab7843bb638c0b5abc
        // c496e8e8f7cc2e40c515c9dbd98ffce43861acaf504466f478ceaebf712214b8

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

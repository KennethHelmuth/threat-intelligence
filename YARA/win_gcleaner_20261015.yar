rule win_gcleaner_20261015
{
    meta:
        description = "Auto-generated stub for win.gcleaner based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-15"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.gcleaner"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // aab3a520dec95e364dcff3fdbbe0e115
        // 9e12a215b0ac52a82e71103a133e2068991bb1efd441f52a170c61778ffd4856

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

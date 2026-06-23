rule win_xworm
{
    meta:
        description = "Auto-generated stub for win.xworm based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-23"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.xworm"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // d9e0461524386292212444734e44619e
        // 6a0bf1dba11b61b4b53e78ccb483a7aea4ec3cfa81d2e7f9de55376c9fdef7ec

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

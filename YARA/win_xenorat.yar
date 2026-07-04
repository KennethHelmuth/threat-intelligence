rule win_xenorat
{
    meta:
        description = "Auto-generated stub for win.xenorat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-04"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.xenorat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0697eae9deae7c2d4039d83539811f17
        // eacea4983eb01cabe9f621d7b28ae37cbc3e801106575272795e025de1064a29

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

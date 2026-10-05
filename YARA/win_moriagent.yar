rule win_moriagent
{
    meta:
        description = "Auto-generated stub for win.moriagent based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-05"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.moriagent"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // a6fd9946588813407f8e625f2450d22874e1dbbf7c0dc602b16786ebed410035
        // c3a2d9c1ae423ae362e76c200f5f3d52

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_glassrat
{
    meta:
        description = "Auto-generated stub for win.glassrat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-27"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.glassrat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // eadf1a5f058ec8811ea87536badb474a
        // c1d38c3132ef3f55b417e898da98a54ac5940537f4c2281bcacc430c4a25f646

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

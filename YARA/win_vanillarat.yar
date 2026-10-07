rule win_vanillarat
{
    meta:
        description = "Auto-generated stub for win.vanillarat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-07"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.vanillarat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // f3cdb85bf342b4efd4abf22ccaeb3cec511b5f6fe7bb9e4f1b9461f090425971
        // 805836d85d002b708ac1693c1117f863

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

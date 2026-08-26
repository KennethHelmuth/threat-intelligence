rule win_evilextractor
{
    meta:
        description = "Auto-generated stub for win.evilextractor based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.evilextractor"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 63f3064a8023989933b7d294af76cd5a583eeea38aedfa464cd2ea2cf3a4ed73
        // e384e7389a371c96e5d31effce1242ae

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

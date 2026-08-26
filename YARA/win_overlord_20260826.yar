rule win_overlord_20260826
{
    meta:
        description = "Auto-generated stub for win.overlord based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.overlord"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 02e0b6dd34553b2d1e4a0f023716061884893d84995b3641b388b02f4e04014d
        // 553f64001e0e802a9619bd934d791155

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

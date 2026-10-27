rule win_xoriumstealer_20261027
{
    meta:
        description = "Auto-generated stub for win.xoriumstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-27"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.xoriumstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0148354adc7a83110247757cad5ac22c
        // c5bc91579693cc41036d835ce4e754f941310cebb73b69628300315df39c2489

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_luca_stealer_20260729
{
    meta:
        description = "Auto-generated stub for win.luca_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.luca_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 00f41782b7ffda43f48a632433f8d70d2363600af03b02182009d72d825ec650
        // 41d9eba31f341c2c2a4cfd6af4a94023

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

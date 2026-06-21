rule win_luca_stealer_20260621
{
    meta:
        description = "Auto-generated stub for win.luca_stealer based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-21"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.luca_stealer"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 2f9ec23d6ca74629b928f5f149d9feb4
        // afa807cee34e8b931688ccf2be76b7ea5337af3d64714a348bead839c756643a
        // 3368d54f30631c9e305f6df3464e08b6b4f24eebdb605240c44b144deed717fa
        // c83776891f0407e6401a7d7004691f86

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

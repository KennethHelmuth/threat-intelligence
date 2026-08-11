rule win_pure_rat_20260811
{
    meta:
        description = "Auto-generated stub for win.pure_rat based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-11"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.pure_rat"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0e260f328a81040da84f79bb21d54953
        // 2a167fbe58a9d874dda8798e9b0d773d9316a217256a7e3f1d0c5e3e26f9f03a
        // 325dd213f9a6f78e41cad30c49e0a178
        // da9442ac1174544216a00fb1792f7ee019cb708e47cd5948a9632e24285b36cb

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_salatstealer_20261113
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 5 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-13"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "5"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 329a6bc97fe8a0151e3183e8670d478a3de377ed8998c542de4fc4f61880ebd4
        // 35a3c714998539eb98a26e7ae58f379378ddf3fdcb67068944cc8c67a016eb04
        // 4d2c3339e61f827a4fde503c775de9ec
        // 52e7dbe125b2d8db65a0ba7bf80aab698e7f54f8b5b51c2f218f5fb2870ed142
        // cb7ffde3b9fcc7c23ebf88eed9a23967

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

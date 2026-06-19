rule banana_rat
{
    meta:
        description = "Auto-generated stub for banana_rat based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-19"
        version     = "1.0"
        source      = "OTX"
        family      = "banana_rat"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 38dfeb772afbd01c04eddda120d283acfb1147a6dc3d54ac62fe23ad06e39d8f
        // 4912b1134e69ade7266e8508eec33ccb2d80ad693f1dbc4f1f4344c6dfcf2ff1
        // d7545b6dacebdae27effb3c778c5e349027ec789c76ae4f777bd9ba56a70cdaa
        // ecdc8fade561a75d68235859ad8b1fe131db2c458b4894268e38e90ecab1c47f

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

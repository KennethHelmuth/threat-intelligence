rule ekz_stealer
{
    meta:
        description = "Auto-generated stub for ekz_stealer based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-27"
        version     = "1.0"
        source      = "OTX"
        family      = "ekz_stealer"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0da123adf9251957a4b850a3f6bd6a753dd4892be176a84a18450e899534cc5e
        // 338662fd0c4d750a0ba203a32b59f081
        // 17e771c78430cc67e71d4547f8996a1a488e9d3f

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

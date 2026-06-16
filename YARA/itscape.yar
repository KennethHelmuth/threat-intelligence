rule itscape
{
    meta:
        description = "Auto-generated stub for itscape based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-16"
        version     = "1.0"
        source      = "OTX"
        family      = "itscape"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // e0ab84da2d2783c8cae3624e8ce58b99ad79219753b249671ff7f743abdacc35
        // 838ea8d6b201e2eed181f3fd890f99ecb6178b52
        // fbf0b6abd651622864eb921f891b3e7c538fc8a9

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

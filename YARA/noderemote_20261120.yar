rule noderemote_20261120
{
    meta:
        description = "Auto-generated stub for noderemote based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-20"
        version     = "1.0"
        source      = "OTX"
        family      = "noderemote"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 80cf452f30aaf7d3f5373b3c7318ff9e
        // 70f920cf7bdc0fea7f3af8e2899e33ca80f8e3df

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

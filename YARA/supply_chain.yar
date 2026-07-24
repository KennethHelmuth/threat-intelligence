rule supply_chain
{
    meta:
        description = "Auto-generated stub for supply_chain based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-24"
        version     = "1.0"
        source      = "OTX"
        family      = "supply_chain"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 572745566ec674c6eae10c179b0de2ba
        // e219da0599dea936ee867792e2dfe6a2c2a7c68b
        // 22f721fd3a81d2e27cbf90a122bb977f630c50b79daa98350f0e57b04dfa81f1

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

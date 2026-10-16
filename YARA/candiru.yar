rule candiru
{
    meta:
        description = "Auto-generated stub for candiru based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-16"
        version     = "1.0"
        source      = "OTX"
        family      = "candiru"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 255869de85e2a171993fc5eb8a556d873a1b8966e040f6f55926f2fa2d595cc8
        // 63c2963a7abc1e4ee083275e5582a52f1101dba9905fd35498726359abf95a71

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

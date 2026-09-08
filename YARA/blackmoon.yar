rule blackmoon
{
    meta:
        description = "Auto-generated stub for blackmoon based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-08"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "blackmoon"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 526e532170acbc980bf41c48d1886b592a871c852d5ea86f98db4296bbbe85b6

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

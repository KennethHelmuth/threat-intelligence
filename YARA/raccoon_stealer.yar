rule raccoon_stealer
{
    meta:
        description = "Auto-generated stub for raccoon_stealer based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-22"
        version     = "1.0"
        source      = "OTX"
        family      = "raccoon_stealer"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // e77221d7a4b47b9107ba1b61a551ca89
        // 95c5ae3fec0d900e4634e11b3ad81971e78e2b31
        // 22ebb950592ccc987fd1dab9ddcd34c4fc519975dc1b82e4a793dc038d2d8e41

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

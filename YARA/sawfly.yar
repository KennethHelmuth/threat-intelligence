rule sawfly
{
    meta:
        description = "Auto-generated stub for sawfly based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-21"
        version     = "1.0"
        source      = "OTX"
        family      = "sawfly"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 1f19b9a27d79c11bda00a1e8faf74a7fdd683d38ccef1b60df2fd0307e3aa462
        // dc14e215269a93fdbc4c1a80b984c23faf7af0911c6dbb85309796a6f2ae95fb

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

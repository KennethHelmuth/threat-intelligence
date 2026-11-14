rule xloader_20261114
{
    meta:
        description = "Auto-generated stub for xloader based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-14"
        version     = "1.0"
        source      = "OTX"
        family      = "xloader"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 5bd3c5f273ba5ae4c4ae745c6943a4f7
        // 8b3542531d98a47524c0f468d0158996
        // e0d7a34bc9f4590bc073d08b50c854d1

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

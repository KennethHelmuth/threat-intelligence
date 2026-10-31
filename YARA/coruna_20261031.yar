rule coruna_20261031
{
    meta:
        description = "Auto-generated stub for coruna based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-31"
        version     = "1.0"
        source      = "OTX"
        family      = "coruna"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 2bd4d305ab5ca9838f654852305f098e
        // 5cd447b2e62778fae8c25bd79bbd757928ab8454

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

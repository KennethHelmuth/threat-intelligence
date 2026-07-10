rule qilin
{
    meta:
        description = "Auto-generated stub for qilin based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-10"
        version     = "1.0"
        source      = "OTX"
        family      = "qilin"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 52fda5c1b9704544f32ee98d9060e689
        // 51d39aa39478beeac94f2d12f682ecce

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

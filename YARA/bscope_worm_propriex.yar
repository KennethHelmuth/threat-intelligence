rule bscope_worm_propriex
{
    meta:
        description = "Auto-generated stub for bscope_worm_propriex based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-30"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "bscope_worm_propriex"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 22eec70bf4412de64eb3ac2aaf1991a7e1ca197f8ec37339fa549e0037908e85

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

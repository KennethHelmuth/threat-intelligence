rule py_venus_stealer_20260930
{
    meta:
        description = "Auto-generated stub for py.venus_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-30"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "py.venus_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 956c4e03e647704a5c6d065b8b024add05966912aeb82b25c62d2905372b6f29
        // 16217862154b09ea92a7628ef168a451

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

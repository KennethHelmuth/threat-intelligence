rule py_rn_stealer_20261116
{
    meta:
        description = "Auto-generated stub for py.rn_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-16"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "py.rn_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 6b80b3ad8404eff97d70fb9994e01b93
        // fdaa8df207ca31ce1a2dc05bbe9036b8

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

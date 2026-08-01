rule py_rn_stealer_20260801
{
    meta:
        description = "Auto-generated stub for py.rn_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-01"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "py.rn_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c05581c54fb2e63ab1b6d0c8957d24fbcbc0e094339bc02838b50b3f72dddeff
        // 9188e2a2bc5f9e23dfb62cff8589ae64

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

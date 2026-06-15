rule win_ghostnet
{
    meta:
        description = "Auto-generated stub for win.ghostnet based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-15"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.ghostnet"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 81a6699618caa9d38a99aac19a33b770
        // 3dc1a7ac46a1616fe180f42e26d25ea9638f90c73073542b49a8575e2f110174

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

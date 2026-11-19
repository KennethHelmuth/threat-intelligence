rule win_mops_stealer
{
    meta:
        description = "Auto-generated stub for win.mops_stealer based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-19"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.mops_stealer"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 6855e86e1742060595ebb402af368258c1dfc69471c2d8aab6c65c3008f66c27
        // fa294a9c80d8e5b9815fccef7519bfa579afbb1de286fdd3a0ef045825d9e3ed
        // bab95b197b992dd680fa567f1f0e70cc94260fb88ce7eca307095d2e28c6013a

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

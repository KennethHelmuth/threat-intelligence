rule win_epsilon_stealer
{
    meta:
        description = "Auto-generated stub for win.epsilon_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-16"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.epsilon_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 6fbacb02382b2a52786994adeed3c8b1
        // 8502dd5e803f7583007481e1821f9242a6ba2774974f6757dd0535a688f6e1b1

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

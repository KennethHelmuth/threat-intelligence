rule win_epsilon_stealer_20261008
{
    meta:
        description = "Auto-generated stub for win.epsilon_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-08"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.epsilon_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 5acb6579fc74d66e67e0cdecddb46457
        // bed116abf922b28f79323cce3901e206e82cb4a37020c623217ff1541baa00f1

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

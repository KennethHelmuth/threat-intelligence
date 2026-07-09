rule win_arkei_stealer_20260709
{
    meta:
        description = "Auto-generated stub for win.arkei_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-09"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.arkei_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 06f915bc056a74c1c9b6faa3098a700ef4e5f54b8b1e84f73c70dcc6f5096949
        // 32ba76496cf54bf0c9302e6ddab64cd9

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

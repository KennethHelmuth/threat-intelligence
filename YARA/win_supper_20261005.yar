rule win_supper_20261005
{
    meta:
        description = "Auto-generated stub for win.supper based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-05"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.supper"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 796897808e7d751ac0007e54a1cd2290da046f9dabcb7a3074f23a6039564256
        // 8c3dd656daaafe66e19afd5cb76d8a7d

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

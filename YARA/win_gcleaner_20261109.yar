rule win_gcleaner_20261109
{
    meta:
        description = "Auto-generated stub for win.gcleaner based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-09"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.gcleaner"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 430a81fa6ef1dc555ed91445ea174accdf2031e75168e2808752211eb1b3e29b

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

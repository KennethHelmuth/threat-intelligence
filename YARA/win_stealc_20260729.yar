rule win_stealc_20260729
{
    meta:
        description = "Auto-generated stub for win.stealc based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 929f05e274f24763222f9649eb3b14f4
        // 4ed3931ab5bddd24ce23fd0d5546ae45b52a0cd0124afe7cb3692a56510ac1ed

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

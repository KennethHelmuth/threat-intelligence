rule win_stealc_20260629
{
    meta:
        description = "Auto-generated stub for win.stealc based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 011c4ffba12eb2a298ff83159177ca7a
        // b2687e641c114589ef0f3e96abb7bdf5758009b72a0ef74f2e7f30fafe7bebe7

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

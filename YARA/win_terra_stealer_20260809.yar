rule win_terra_stealer_20260809
{
    meta:
        description = "Auto-generated stub for win.terra_stealer based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-09"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.terra_stealer"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 8401e96f3e47f9e0fb2544424acd1434

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

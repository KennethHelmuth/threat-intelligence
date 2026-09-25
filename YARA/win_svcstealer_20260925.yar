rule win_svcstealer_20260925
{
    meta:
        description = "Auto-generated stub for win.svcstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-25"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.svcstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c705fea2fd2e6c119c1138f1b74cd798
        // 221e2c855e78d5cc7fb84738effb88bb11a47be6ce10530c909534e15f47e0b4

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

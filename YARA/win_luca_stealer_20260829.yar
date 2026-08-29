rule win_luca_stealer_20260829
{
    meta:
        description = "Auto-generated stub for win.luca_stealer based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.luca_stealer"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // bb65c6e1104854b87418a16fffd59230
        // b926a44910e4f4d55c53fdc6d9cdbfb043059355d55fb3595a3434bd69b1e7e3
        // 38588342e64c159b60e1530aef1081bc
        // d47a793404c4bb0419c9ae1fda9847aa6a75a029e60ed65f05645dad9ee9573b

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

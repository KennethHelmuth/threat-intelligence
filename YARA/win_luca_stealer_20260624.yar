rule win_luca_stealer_20260624
{
    meta:
        description = "Auto-generated stub for win.luca_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-24"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.luca_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // b45bbb0582aa658722616257d7cde23eb98430a2f31dbac3de596365122a642f
        // b97769a9e25a997a29d8b849800ac541

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

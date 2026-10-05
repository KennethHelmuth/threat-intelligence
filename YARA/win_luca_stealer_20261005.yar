rule win_luca_stealer_20261005
{
    meta:
        description = "Auto-generated stub for win.luca_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-05"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.luca_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c24fdcd921be5cca6f0ee11156a6bd7d
        // ed69b232a3ac92a5e5f43757119af730f5d814305122a456132dad36a1d6a5fd

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_pure_rat_20260829
{
    meta:
        description = "Auto-generated stub for win.pure_rat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.pure_rat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 2ca17777470b32e4e74b547e5f3f9306
        // f63eb2664ac9076250491b1cb0787042f75a056e235867d9f9967322c5cf20a4

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

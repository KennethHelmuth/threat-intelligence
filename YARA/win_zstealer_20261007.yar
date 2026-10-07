rule win_zstealer_20261007
{
    meta:
        description = "Auto-generated stub for win.zstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-07"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.zstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 722552977aa29059abd535e5ed5b92e3de3a31e269d92210845672f4894f3404
        // 74e28ff56ee527fe955e404861a4c71b

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

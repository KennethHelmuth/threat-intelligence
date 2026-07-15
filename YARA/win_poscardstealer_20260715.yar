rule win_poscardstealer_20260715
{
    meta:
        description = "Auto-generated stub for win.poscardstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-15"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.poscardstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 9115c69843820f1a93b137bf6eab805294d61bfee04b971b7df01de2c927a12b
        // 7866e055d6135c7fcbebc7bbdb8266d5

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_poscardstealer
{
    meta:
        description = "Auto-generated stub for win.poscardstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-18"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.poscardstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 51335ef0e92ee549c9ec24338935d1b3
        // 994360679da88dedbdcc0563919e2b9c7c717aa1acc1620e8bc489a2daa97ac9

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

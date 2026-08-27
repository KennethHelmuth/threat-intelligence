rule win_valley_rat_20260827
{
    meta:
        description = "Auto-generated stub for win.valley_rat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-27"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.valley_rat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 2fd2d9bc5106a3b5379269926b0feb43
        // 78a29a09726ad370e782cbd3e88490cecea695112f9171d9d8168a18b25ef67b

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

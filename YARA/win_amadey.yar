rule win_amadey
{
    meta:
        description = "Auto-generated stub for win.amadey based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-21"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.amadey"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 9be1777c6150a1a50e4961902a487ef5
        // 29352f59456553b5f5484561ad72727866119f00dfa50626b152ec47d68369a9

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

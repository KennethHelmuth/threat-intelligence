rule win_formbook_20261115
{
    meta:
        description = "Auto-generated stub for win.formbook based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-15"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.formbook"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 3a1e7d2aaeb545d10018b4925a321de02d6ee47122de46c11c701b25a4f08d59
        // 9b1933ff196a946f3b43fdf9a4bea548301b8490f4142c3c3064c0c1a44a7946

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_gcleaner_20261011
{
    meta:
        description = "Auto-generated stub for win.gcleaner based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-11"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.gcleaner"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 45b8c5064a92c60ea747e3bdd7dbe201fe8577942c048f1e942e9237e3b9a6ec
        // 8d1d55cdb009796323a6ffe8c3403795

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

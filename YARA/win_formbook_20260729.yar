rule win_formbook_20260729
{
    meta:
        description = "Auto-generated stub for win.formbook based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.formbook"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c189e889e530d891501d459eea14af09e51af8f489cfb827cca985af057f2276
        // a560021ea970572d26d453d3d02ccb25
        // 9ed59215e24621404e058f8c0e9101e9351e147f5b367679b8d62ec73f44d169
        // a11bc7fddad2602881739faab6875ad6
        // 8d1bcf322230e8935758228cebec1bb6
        // a3ab968ecfe40961e381aff0e5bba919eb4e8cfcbbf445cf44441197aefbb399

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

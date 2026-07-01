rule win_easystealer
{
    meta:
        description = "Auto-generated stub for win.easystealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-01"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.easystealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 3f0352cbeaaec5e6bb9cad551a9b7007
        // 7d2370b8831dd07db1346424e487534db6079ffc9472a4a1710f8b9fcd78c182

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_dostealer_20260731
{
    meta:
        description = "Auto-generated stub for win.dostealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-31"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.dostealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 7be016472fd1c64cd6d6ec831f3fb0452afb38d45f4d3f1b9925963f6e4d38ff
        // b13c5a28695f4997c780c43357638f54

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_gunra
{
    meta:
        description = "Auto-generated stub for win.gunra based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-28"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.gunra"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 834EFE9B392C6C000877EA5613A079445AFFC16FE8AF5997D68C55CAFC95E5D1
        // 2DC70A12D158D437E45A55B1D52F3D61C6082A1E1667573302BA3B62813E2751

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

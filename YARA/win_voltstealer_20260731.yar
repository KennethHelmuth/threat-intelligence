rule win_voltstealer_20260731
{
    meta:
        description = "Auto-generated stub for win.voltstealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-31"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.voltstealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // a28a36d807a8f3c888d8ca0f07f66875
        // ed14cfe70eedac6e7a3097baa94b84f21e358bdb2361f7da5b5e8a42cdb8ba7c

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

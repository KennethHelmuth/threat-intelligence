rule py_stealler_20260626
{
    meta:
        description = "Auto-generated stub for py.stealler based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "py.stealler"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // a64eee9ab72607f0f5b69d6bb3871586767b8b3e46f23d3154833bada493afb5
        // 215d24f82100037b3b0212c7a53166e6

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

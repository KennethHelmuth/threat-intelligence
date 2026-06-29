rule win_amadey_20260629
{
    meta:
        description = "Auto-generated stub for win.amadey based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.amadey"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c1cda5f5016b812993dd4858fa6fb949
        // c942ecd62cc2de17119903a9adb79dc9a382136288a2a5e9385e856a668a3d7a

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

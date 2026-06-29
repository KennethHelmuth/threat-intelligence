rule win_dostealer_20260629
{
    meta:
        description = "Auto-generated stub for win.dostealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-29"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.dostealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // dced1923790be572edf4191106a6dc10
        // d6d38c1850e229809385420e9473ebd68fc9ade8d3d2b25052c476741db52bda

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

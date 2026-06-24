rule win_dostealer_20260624
{
    meta:
        description = "Auto-generated stub for win.dostealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-24"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.dostealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c8525c9380f5c3d9d5c66e101120fee50c3e4a80d0981507d300b33a6cafb208
        // a1730a346e6f5ee77650976177a17e68

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

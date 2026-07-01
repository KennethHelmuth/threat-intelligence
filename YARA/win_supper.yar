rule win_supper
{
    meta:
        description = "Auto-generated stub for win.supper based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-01"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.supper"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // dec98a1ef5d1d1b5a6aa886345de1ac4adcea5829509e375b7cf87b7a22fb91d
        // caf61d5d2d0449eba635f900da57c26c

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

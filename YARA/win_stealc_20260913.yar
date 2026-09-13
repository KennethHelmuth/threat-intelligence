rule win_stealc_20260913
{
    meta:
        description = "Auto-generated stub for win.stealc based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-13"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 7e7c5bf4ee226dfad50acf391570cecb
        // 05dbb515120ec8a6a453c91833eacf432e67ffe89fd650ac704eefc6bf8de290
        // 71134e2462c403b76fa25455f26313a45cd1973da6882cbdea5d8c04b47e18f3
        // d85bfa6b949a3323f903344027fe4206

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

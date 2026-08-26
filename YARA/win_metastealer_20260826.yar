rule win_metastealer_20260826
{
    meta:
        description = "Auto-generated stub for win.metastealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-26"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.metastealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 5bd1f26001082fb7888e986fd6b60df09d4ef91e438741dce7a2fe937644c764
        // 3c3fd9cd6a4bc0d223970bc7d7341269

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

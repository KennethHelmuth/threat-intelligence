rule win_metastealer
{
    meta:
        description = "Auto-generated stub for win.metastealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-15"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.metastealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 8aa5c3cd3117f58ff76888ec83157436c775c87600b4c1b6c2620b93e5d41271
        // 1dc9b9053a4c36993b761696745cc724

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

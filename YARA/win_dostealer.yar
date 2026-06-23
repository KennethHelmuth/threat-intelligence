rule win_dostealer
{
    meta:
        description = "Auto-generated stub for win.dostealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-23"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.dostealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c76ecf8d8dc484a7cbfc0b43e286e97a
        // 68b472722874374a6132ce1ec9470b14b7030030602d740fd5038d6560264c68

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_salatstealer_20260911
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-11"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c964a9c1f74420abb9006a3b2e3738729517eab0c112f8e7f34864878b18fcbe

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

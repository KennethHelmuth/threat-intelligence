rule win_njrat_20260725
{
    meta:
        description = "Auto-generated stub for win.njrat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-25"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.njrat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 306038f5b80551285855f65f1cc13045
        // 71b9449efaa11bc7e3e82a3df58a0730faae3b0e4ed1f96b36f71a4d675e872c

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

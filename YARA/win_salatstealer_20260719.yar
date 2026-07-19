rule win_salatstealer_20260719
{
    meta:
        description = "Auto-generated stub for win.salatstealer based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-19"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.salatstealer"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 58224bee686c03b0f7394a459d3ff971
        // 466d3130f4f427ec39fb1378ee142e6f
        // f2b9739fe3aced2d2074db022b5d1e23003b44fbc24413f3bd3298f1623c6665
        // 16a4a7b5a478ce3dd732b318f7dfadbd337ab51d804a0a261623ea941417fd5f

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_luca_stealer_20260728
{
    meta:
        description = "Auto-generated stub for win.luca_stealer based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-28"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.luca_stealer"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c037ac52a26a18e7b2e911415e85a080
        // 8cf7bbe8eb52f88bf5c7129b4923acff510275d5c47a38bf82667c102e6e8c9a
        // 5fae196b68afca48ce650acc79e25126
        // 56cc93be915c0d59943d0bf3c91dc1956b0af95939b812679197d3607829713f

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

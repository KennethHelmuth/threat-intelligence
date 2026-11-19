rule win_orcarat
{
    meta:
        description = "Auto-generated stub for win.orcarat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-19"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.orcarat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 01a0817b561a580d310cf4c5a37de1a3
        // 4e9fe38b5eed9b20de37d2f0a2cb2282b319f522fa878962aaa29ccf833346ef

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

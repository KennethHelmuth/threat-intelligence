rule win_pony
{
    meta:
        description = "Auto-generated stub for win.pony based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-16"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.pony"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0a113920a5b5f7aa23f5280307fa0b8d
        // d57a32639b2f1365751d4d6a771a32b514c1185556c94e46b087add06bd3523b

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

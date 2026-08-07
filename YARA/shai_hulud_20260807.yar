rule shai_hulud_20260807
{
    meta:
        description = "Auto-generated stub for shai-hulud based on 3 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-07"
        version     = "1.0"
        source      = "OTX"
        family      = "shai-hulud"
        hash_count  = "3"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // bbbca2ddaa5d8feaa63e36b76fdaad77386f024f
        // de0fac2e4500dabe0009e67214ff5f5447ce83dd
        // 29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

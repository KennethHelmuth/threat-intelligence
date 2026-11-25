rule win_gcleaner_20261125
{
    meta:
        description = "Auto-generated stub for win.gcleaner based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-25"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.gcleaner"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 26194ae00bd4cc4cdd09810b244b5e536c1dc66a048b85bd7985cb94a99621aa

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

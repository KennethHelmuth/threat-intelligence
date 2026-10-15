rule win_luca_stealer_20261015
{
    meta:
        description = "Auto-generated stub for win.luca_stealer based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-15"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.luca_stealer"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // f736c6c9fcfb2608480270a303eceaee
        // 2fe60b18bb97ad7ea8bc8f746be851205e59ed68cd2244784ef0d052758e4346

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

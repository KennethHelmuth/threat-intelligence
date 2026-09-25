rule win_stealc_20260925
{
    meta:
        description = "Auto-generated stub for win.stealc based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-25"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.stealc"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 17f99c347607bdc506be5f204afe1d03c0c09a9f1aceaf11019b2941413d59e4

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule win_agent_tesla_20260704
{
    meta:
        description = "Auto-generated stub for win.agent_tesla based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-04"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.agent_tesla"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // e634daa853d4d5a55ad3ee5d20d336a9
        // 31d293ffa5e55ff2df504ab951b785e902b335974826a9bfbcd4dfb29ab59068
        // c189e3cd9342923a743770f191bd70cc
        // 7dd595347aea3817cde5da19e3a6b76adf2f0baef0ecbd67ff3d80be1d5930a4

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

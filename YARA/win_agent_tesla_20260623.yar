rule win_agent_tesla_20260623
{
    meta:
        description = "Auto-generated stub for win.agent_tesla based on 6 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-23"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.agent_tesla"
        hash_count  = "6"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // bd9d6c8361b4d9ab9cf22f177273ca03
        // 2009c2095160ce4c016855f7af23529a143e7533a5624b60f4dbc277ae9a7bbf
        // 50f80b086aac1820defd105200518c2f
        // 9b76d12f3786d918ffd01eefedd10026
        // 99bee9c7498d8bbf660140795ad31220000a408d8234f58bed07939779ce0ed4
        // 1d47d23590a3fa04729bb611f7b69356b47639667b83cdfe38eeee77e7f1601c

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

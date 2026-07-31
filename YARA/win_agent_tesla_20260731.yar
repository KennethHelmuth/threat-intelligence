rule win_agent_tesla_20260731
{
    meta:
        description = "Auto-generated stub for win.agent_tesla based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-31"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.agent_tesla"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 9eab119e1a445bdb9276dc76d572e20b
        // a6eb7f69df025bf0229d9d3a9754cf687e8165978fd2fcf3accd30c6afa67562

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

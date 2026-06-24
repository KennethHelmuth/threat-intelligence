rule win_agent_tesla_20260624
{
    meta:
        description = "Auto-generated stub for win.agent_tesla based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-24"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.agent_tesla"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 214e97b9f597cbb2422a4cf062c8154f
        // 059f89bc7b83b669362cb3ce1182508255c2e97c296c1b9820415d0a9b1ba3d5

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule linux_agent_bgd_trojan
{
    meta:
        description = "Auto-generated stub for linux/agent_bgd_trojan based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-07"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "linux/agent_bgd_trojan"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 5d7004c89597bbdbca578f3f441c2a61ffe89a6afdaf9c953fac8163890379a6

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

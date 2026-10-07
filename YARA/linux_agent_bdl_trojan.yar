rule linux_agent_bdl_trojan
{
    meta:
        description = "Auto-generated stub for linux/agent_bdl_trojan based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-07"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "linux/agent_bdl_trojan"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 040a0da5c3f26dc1b971271e13e8930c7680b8aeef8aba87f885009760a71709

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

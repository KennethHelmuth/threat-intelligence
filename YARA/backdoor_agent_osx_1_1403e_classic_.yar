rule backdoor_agent_osx_1_1403e_classic_
{
    meta:
        description = "Auto-generated stub for backdoor_agent/osx!1_1403e_(classic) based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-27"
        version     = "1.0"
        source      = "OTX"
        family      = "backdoor_agent/osx!1_1403e_(classic)"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 05e1761b535537287e7b72d103a29c4453742725600f59a34a4831eafc0b8e53

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

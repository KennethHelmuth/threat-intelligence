rule bash_agent_aof_tr_20260620
{
    meta:
        description = "Auto-generated stub for bash/agent_aof!tr based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-06-20"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "bash/agent_aof!tr"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 8bedf6ba4034dde861d0ca248a44c98d90e066f3631a1d1d72a8c5b2df849843

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

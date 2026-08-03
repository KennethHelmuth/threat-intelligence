rule bash_agent_aof_tr_20260803
{
    meta:
        description = "Auto-generated stub for bash/agent_aof!tr based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-03"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "bash/agent_aof!tr"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 76c488739cdb46ae9bea8ab5d34fb49e7345fba3bcdb9cf3b24cc2e7cd7667f2
        // 9554d42935b9036d49d299e582e1488b3e55fe27f2745ae49955a06a06425584

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule bash_agent_aof_tr_20260718
{
    meta:
        description = "Auto-generated stub for bash/agent_aof!tr based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-07-18"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "bash/agent_aof!tr"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 296a72481bfbddcfc395c8e0ed3b6c3c0489530f8c20c90f60c519c4cb73e3df
        // 7961c4cb8175e03c7a6ab0cef01d0b0feaecc2fe3b25b7c8a036ce3051135284

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule heur_trojandownloader_linux_agent_am
{
    meta:
        description = "Auto-generated stub for heur:trojandownloader/linux_agent_am based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-17"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "heur:trojandownloader/linux_agent_am"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // d7234d9249e7cc454cc684c0e7b124a32f4df870e1cac86188d8eeaf36f6819c

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

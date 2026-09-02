rule noderabbit
{
    meta:
        description = "Auto-generated stub for noderabbit based on 4 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-02"
        version     = "1.0"
        source      = "OTX"
        family      = "noderabbit"
        hash_count  = "4"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // da11679653ef33952c3dc8d8850e43d7b8ac884a
        // 0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864
        // f0c8db403231d478f67df0355328c58384027677
        // 307ce2448211a5f5d122643f2a739aff33ede72c1858518c8de098f3148bbd00

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

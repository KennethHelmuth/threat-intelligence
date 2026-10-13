rule netsupport_20261013
{
    meta:
        description = "Auto-generated stub for netsupport based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-10-13"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "netsupport"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 05bdc12486c7b3f60e07653b3411be4beee7a29a6547bacd1b775717dbc4ea31

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

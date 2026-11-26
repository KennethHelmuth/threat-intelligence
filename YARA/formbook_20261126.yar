rule formbook_20261126
{
    meta:
        description = "Auto-generated stub for formbook based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-26"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "formbook"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // c4df5fc57e9ffcb20022fa8d24b07db5b5851607dfb295e1314cd54d785131f9
        // 4978c249869c364f4944e7da41c0a9f1e6dac9e54dbcfbf53e02e162c1246bc3

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

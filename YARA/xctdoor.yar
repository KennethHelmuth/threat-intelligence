rule xctdoor
{
    meta:
        description = "Auto-generated stub for xctdoor based on 5 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-07"
        version     = "1.0"
        source      = "OTX"
        family      = "xctdoor"
        hash_count  = "5"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 0d2e61c8a5e6280e065b61e75b848c68
        // 12391f66ee33d379108fd649a999e1a0
        // 01b58f2ff2c14feed46a0768ea46686d
        // 07766e6e9d9f86775ad564a65af292c1
        // 08e19a0d516d14e564359ee111ed2586

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

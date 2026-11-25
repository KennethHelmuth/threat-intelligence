rule xworm_20261125
{
    meta:
        description = "Auto-generated stub for xworm based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-25"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "xworm"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // f1569455e60aa5629f3095c6755cc8a01c7c079ff260824e411fae2ee532206b

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

rule stealc
{
    meta:
        description = "Auto-generated stub for stealc based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-27"
        version     = "1.0"
        source      = "MalwareBazaar"
        family      = "stealc"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // bd272ade659825489680409b8203fa0849a67e415b3b27b3a84af278c11ae94b
        // b8333cb31310f8c54917e3b10c54ff1089bab17f1db6328bf34a00890396a67e

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

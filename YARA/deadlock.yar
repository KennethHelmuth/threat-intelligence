rule deadlock
{
    meta:
        description = "Auto-generated stub for deadlock based on 1 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-08-12"
        version     = "1.0"
        source      = "OTX"
        family      = "deadlock"
        hash_count  = "1"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // a1fdf65020ce4a0f0940c793c6425baf8a0b994ec48b9baaf72788661a9d29f4

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

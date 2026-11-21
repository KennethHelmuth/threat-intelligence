rule unknown_loader_20261121
{
    meta:
        description = "Auto-generated stub for unknown_loader based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-11-21"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "unknown_loader"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 6decb836e9296b6ff86e372532c17be886adf3581a0ebdc2589d656bdc448227
        // bebece5736b960e23173630703894836c39fc654e46ae6e6d4adfa2c8a157b74

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}

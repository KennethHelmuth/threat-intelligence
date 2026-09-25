rule win_shimrat
{
    meta:
        description = "Auto-generated stub for win.shimrat based on 2 hashes"
        author      = "ti-pipeline (auto-generated)"
        date        = "2026-09-25"
        version     = "1.0"
        source      = "ThreatFox"
        family      = "win.shimrat"
        hash_count  = "2"

    strings:
        // Hashes (SHA-256) – reference only; add byte-strings/imphash conditions below
        // 94ffe61fb9619a00d8c1066dc8728df2af733f0b9ca8783a93ecbe1e52e59562
        // e629a420112f2bcb593f5467a362a91a

    condition:
        // TODO: replace with byte-level strings, pe.imphash(), or hash.sha256() checks
        // Example: pe.imphash() == "aabbccdd..."
        false  // stub – analyst must complete this rule
}
